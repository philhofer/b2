package b2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Capabilities is a bitmask of capabilities
type Capabilities uint

const (
	CapListKeys Capabilities = 1 << iota
	CapWriteKeys
	CapDeleteKeys
	CapListBuckets
	CapListAllBucketNames // for S3 ListBuckets
	CapReadBuckets
	CapWriteBuckets
	CapDeleteBuckets
	CapListFiles
	CapReadFiles
	CapShareFiles
	CapWriteFiles
	CapDeleteFiles
	CapReadBucketEncryption
	CapWriteBucketEncryption
)

var str2cap map[string]Capabilities

var captable = []struct {
	cap  Capabilities
	name string
}{
	{CapListKeys, "listKeys"},
	{CapWriteKeys, "writeKeys"},
	{CapDeleteKeys, "deleteKeys"},
	{CapListBuckets, "listBuckets"},
	{CapListAllBucketNames, "listAllBucketNames"},
	{CapReadBuckets, "readBuckets"}, // not documented, but returned from the API nonetheless...
	{CapWriteBuckets, "writeBuckets"},
	{CapDeleteBuckets, "deleteBuckets"},
	{CapListFiles, "listFiles"},
	{CapReadFiles, "readFiles"},
	{CapShareFiles, "shareFiles"},
	{CapWriteFiles, "writeFiles"},
	{CapDeleteFiles, "deleteFiles"},
	{CapReadBucketEncryption, "readBucketEncryption"},
	{CapWriteBucketEncryption, "writeBucketEncryption"},
}

func init() {
	str2cap = make(map[string]Capabilities, len(captable))
	for i := range captable {
		str2cap[captable[i].name] = captable[i].cap
	}
}

type buffer interface {
	io.Writer
	io.ByteWriter
	WriteString(string) (int, error)
}

func (c *Capabilities) write(w buffer, quote bool) {
	written := 0
	for i := range captable {
		if *c&captable[i].cap != 0 {
			if written != 0 {
				w.WriteByte(',')
			}
			if quote {
				w.WriteByte('"')
			}
			w.WriteString(captable[i].name)
			if quote {
				w.WriteByte('"')
			}
			written++
		}
	}
}

// String implements fmt.Stringer
//
// Capability strings are represented as
// a comma-separated list of capabilities,
// e.g. "readFiles,writeFiles,deleteFiles"
func (c *Capabilities) String() string {
	if *c == 0 {
		return "(unknown)"
	}
	var str strings.Builder
	c.write(&str, false)
	return str.String()
}

// ParseCapabilities parses a comma-separated list
// of capabilities.
func ParseCapabilities(s string) (Capabilities, error) {
	list := strings.Split(s, ",")
	c := Capabilities(0)
	for i := range list {
		cs := list[i]
		if mask, ok := str2cap[cs]; ok {
			c |= mask
		} else {
			return 0, fmt.Errorf("bad cap string %q", cs)
		}
	}
	return c, nil
}

// MarshalJSON implements json.Marshaler
func (c Capabilities) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	c.write(&buf, true)
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// UnmarshalJSON implements json.Unmarshaler
func (c *Capabilities) UnmarshalJSON(buf []byte) error {
	var caps []string
	if err := json.Unmarshal(buf, &caps); err != nil {
		return err
	}
	*c = 0
	for _, s := range caps {
		cap, ok := str2cap[s]
		if !ok {
			return fmt.Errorf("unrecognized capability %q", s)
		}
		*c |= cap
	}
	return nil
}

func checkURL(text string) (string, error) {
	u, err := url.Parse(text)
	if err != nil {
		return "", err
	}
	// refuse obviously insecure schemes
	if u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return u.Host, nil
}

type debouncer struct {
	sync.Mutex
	sync.Cond
	count  int32
	locked bool
}

func (d *debouncer) init() {
	d.Cond.L = &d.Mutex
}

// acquire the lock to read fields
func (d *debouncer) rlock() int32 {
	d.Lock()
	for d.locked {
		d.Wait()
	}
	return d.count
}

// release the read lock
func (d *debouncer) runlock() {
	d.Unlock()
}

// conditionally acquire the write lock
// based on the staleness of a previous
// read lock acquisition
func (d *debouncer) acquire(n int32) bool {
	d.Lock()
	ok := false
	if !d.locked && n == d.count {
		d.locked = true
		ok = true
	}
	d.Unlock()
	return ok
}

// release the write lock
func (d *debouncer) release() {
	d.Lock()
	if !d.locked {
		panic("bad release()")
	}
	d.locked = false
	d.count++
	d.Broadcast()
	d.Unlock()
}

type urlentry struct {
	orig      time.Time
	next      *urlentry
	url, auth string
}

// b2 'upload authorizations' can be re-used
// to upload additional files, and re-using them
// saves an enormously expensive (~500ms) round-trip
// on each upload, so this is a cache to hold on
// to them for up to 24 hours (the documented expiration time)
const uploadExpiry = 24 * time.Hour

type urlcache struct {
	sync.Mutex
	tbl map[string]*urlentry
}

func (u *urlcache) get(bucket string) *urlentry {
	u.Lock()
	defer u.Unlock()
	if u.tbl == nil {
		u.tbl = make(map[string]*urlentry)
		return nil
	}
	e := u.tbl[bucket]
	for e != nil && time.Since(e.orig) >= uploadExpiry {
		e = e.next
	}
	if e == nil {
		delete(u.tbl, bucket)
	} else {
		u.tbl[bucket] = e.next
		e.next = nil
	}
	return e
}

func (u *urlcache) put(bucket string, ent *urlentry) {
	if ent.orig.IsZero() || time.Since(ent.orig) >= uploadExpiry {
		return
	}
	u.Lock()
	defer u.Unlock()
	if u.tbl == nil {
		u.tbl = make(map[string]*urlentry)
	}
	next := u.tbl[bucket]
	for next != nil && time.Since(next.orig) >= uploadExpiry {
		next = next.next
	}
	ent.next = next
	u.tbl[bucket] = ent
}

// Client represents a client to the Backblaze b2 API.
// It represents an authorization token associated with
// a particular key.
//
// Typically, a client should be constructed using Authorize().
// All of the methods on Client are safe to call concurrently.
type Client struct {
	// mutable fields; updated every time the
	// auth token expires
	mut struct {
		debouncer
		api, dl           string // api and download hostnames
		partsz, minpartsz int64  // part size, min part size
		auth              string // current auth token
	}

	// cache upload authorizations, since they
	// can be re-used, and it saves a (slow!) round-trip
	//
	// the B2 documentation is unclear about whether or
	// not concurrent uploads to a given url are safe (???)
	// so they are pulled out of the cache when used
	uploads urlcache

	// Key is the key currently being used by the Client.
	// Users should treat this field as read-only.
	Key Key

	// Client is the http.Client used to make requests.
	// If Client is nil, then http.DefaultClient is used.
	// It is not safe to mutate this field with any
	// other concurrent use of this struct.
	Client *http.Client

	// AutoRenew determines whether or not the client
	// automatically fetches a new auth token when
	// it receives a response that the auth token
	// has expired. It is not safe to mutate this
	// field concurrently with any other use of this
	// struct.
	// If AutoRenew is unset, then callers should
	// expect to receive more error returns of
	// type *b2.Error where (*b2.Error).Temporary()
	// is true.
	AutoRenew bool

	// AutoRetry determines whether or not the
	// client automatically retries requests
	// that fail with a 408, 429, or 503 status code.
	// For 429 responses, the client will sleep
	// for the time indicated by the
	// "Retry-After" header.
	AutoRetry bool
}

// Error represents an error returned from the B2 API
type Error struct {
	Op      string `json:"-"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Temporary returns whether the operation that produced this
// error would likely succeed if re-tried.
func (e *Error) Temporary() bool {
	switch e.Status {
	case 408, 429, 503:
		// TODO: figure out how to handle 429s more gracefully;
		// we should respect the Retry-After reponse header
		// if it is present...
		return true
	case 401:
		return e.Code == "expired_auth_token" || e.Code == "bad_auth_token"
	default:
		return false
	}
}

// Error implements the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("b2 %s: %s (code %d, %q)", e.Op, e.Message, e.Status, e.Code)
}

func do(cl *http.Client, op string, req *http.Request) (*http.Response, error) {
	if cl == nil {
		cl = http.DefaultClient
	}
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		e := new(Error)
		json.NewDecoder(res.Body).Decode(e)
		e.Op = op
		res.Body.Close()
		return nil, e
	}
	return res, nil
}

// Authorize returns a Client that can be used for subsequent operations.
// This call assumes the caller has already obtained a B2 app key through
// some other means.
// The only fields in 'k' that are required are k.ID and k.Value.
// Other fields are ignored when constructing the client.
func (k *Key) Authorize(cl *http.Client) (*Client, error) {
	out := new(Client)
	out.AutoRenew = true
	err := k.authorize(cl, out, true)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (k *Key) authorize(cl *http.Client, dst *Client, init bool) error {
	if k.Value == "" {
		return fmt.Errorf("cannot Authorize() key with empty value")
	}
	req, err := http.NewRequest("GET", "https://api.backblazeb2.com/b2api/v1/b2_authorize_account", nil)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth(k.ID, k.Value)
	res, err := do(cl, "b2_authorize_account", req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	val := struct {
		ID      string `json:"accountId"`
		Auth    string `json:"authorizationToken"`
		Allowed struct {
			Cap        Capabilities `json:"capabilities"`
			BucketID   string       `json:"bucketId"`
			BucketName string       `json:"bucketName"`
			Prefix     string       `json:"namePrefix"`
		} `json:"allowed"`
		URL         string `json:"apiUrl"`
		Download    string `json:"downloadUrl"`
		PartSize    int64  `json:"recommendedPartSize"`
		MinPartSize int64  `json:"absoluteMinimumPartSize"`
	}{}

	err = json.NewDecoder(res.Body).Decode(&val)
	if err != nil {
		return err
	}

	// client.Key is immutable after the first time
	// we construct the client; the presumption here
	// is that B2 keys do not have mutable capabilities/restrictions
	if init {
		dst.mut.init()
		k.Cap = val.Allowed.Cap
		k.AccountID = val.ID
		k.OnlyBucket = val.Allowed.BucketName
		k.OnlyPrefix = val.Allowed.Prefix
		dst.Key = *k
		dst.Client = cl
	} else if !dst.mut.locked {
		panic("race in authorize()")
	}

	dst.mut.auth = val.Auth
	dst.mut.partsz = val.PartSize
	dst.mut.minpartsz = val.MinPartSize

	dst.mut.api, err = checkURL(val.URL)
	if err != nil {
		return fmt.Errorf("refusing bad api url %q", val.URL)
	}
	dst.mut.dl, err = checkURL(val.Download)
	if err != nil {
		return fmt.Errorf("refusing bad download url %q", val.Download)
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

func (c *Client) apiHost() string {
	c.mut.Lock()
	h := c.mut.api
	c.mut.Unlock()
	return h
}

func (c *Client) apireq(method, path string, body interface{}) (*http.Request, int32) {
	buf, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	seq := c.mut.rlock()
	auth := c.mut.auth
	host := c.mut.api
	c.mut.runlock()
	req := &http.Request{
		URL: &url.URL{
			Scheme: "https",
			Host:   host,
			Path:   path,
		},
		Header: make(http.Header),
		Method: method,
		Body:   ioutil.NopCloser(bytes.NewReader(buf)),
		GetBody: func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bytes.NewReader(buf)), nil
		},
		ContentLength: int64(len(buf)),
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.FormatInt(int64(len(buf)), 10))
	return req, seq
}

func (c *Client) has(cap Capabilities) bool {
	return c.Key.Cap&cap == cap
}

func (c *Client) renew(res *http.Response, inerr *Error, seq int32) error {
	if res.StatusCode != inerr.Status {
		return fmt.Errorf("b2 misbehaving: json says code %d; HTTP says %d", inerr.Status, res.StatusCode)
	}
	if !inerr.Temporary() {
		return inerr
	}

	// AutoRenew governs 401 handling;
	// AutoRetry governs other temporaries
	if inerr.Status == 401 {
		if !c.AutoRenew {
			return inerr
		}
	} else if !c.AutoRetry {
		return inerr
	}

	if inerr.Status == 429 {
		// try to honor 429 responses
		// like the b2 documentation suggests...
		str := res.Header.Get("Retry-After")
		if str != "" {
			sec, err := strconv.ParseInt(str, 64, 0)
			if err == nil {
				time.Sleep(time.Duration(sec) * time.Second)
			}
		}
	}
	// if another goroutine got around to starting
	// an authorization while this one was performing
	// a request, then simply return and try the
	// request again
	if !c.mut.acquire(seq) {
		return nil
	}
	err := c.Key.authorize(c.Client, c, false)
	c.mut.release()
	return err
}

func (c *Client) api(op string, body, res interface{}) error {
again:
	req, seq := c.apireq("POST", "/b2api/v1/"+op, body)
	hres, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer hres.Body.Close()
	d := json.NewDecoder(hres.Body)
	if hres.StatusCode != 200 {
		e := &Error{Op: op, Status: hres.StatusCode}
		d.Decode(e)
		err = c.renew(hres, e, seq)
		if err == nil {
			goto again
		}
		return err
	}
	return d.Decode(res)
}

// FileInfo represents information about a file.
type FileInfo struct {
	Type        string            `json:"action"`             // "upload" or "folder"
	ContentType string            `json:"contentType"`        // ContentType is the value of the Content-Type HTTP header
	ID          string            `json:"fileId"`             // ID is the file ID
	Name        string            `json:"fileName"`           // Name is the file name
	Bucket      string            `json:"-"`                  // Bucket is the bucket containing the file
	Size        int64             `json:"size"`               // Size is the size of the file
	Extra       map[string]string `json:"fileInfo,omitempty"` // Extra contains extra file metadata
	Timestamp   int64             `json:"uploadTimestamp"`    // Timestamp, unix milliseconds
}

func (f *FileInfo) Created() time.Time {
	return time.Unix(f.Timestamp/1000, (f.Timestamp%1000)*1000000)
}

// FromOSInfo populates the Name and Size
// fields of the receiver based on the
// provided os.FileInfo.
// If the receiver's ContentType field is
// empty, the ContentType will be determined
// from the file extension.
func (f *FileInfo) FromOSInfo(fi os.FileInfo) {
	name := fi.Name()
	f.Name = name
	f.Size = fi.Size()
	if f.ContentType == "" {
		sys := fi.Sys()
		if of, ok := sys.(*FileInfo); ok && of.ContentType != "" {
			f.ContentType = of.ContentType
		} else if ext := filepath.Ext(name); ext != "" {
			f.ContentType = mime.TypeByExtension(ext)
		}
	}
}

// wrapper around *FileInfo that implements os.FileInfo
type osInfo struct {
	f *FileInfo
}

var _ os.FileInfo = osInfo{}

func (o osInfo) Name() string       { return o.f.Name }
func (o osInfo) Size() int64        { return o.f.Size }
func (o osInfo) ModTime() time.Time { return o.f.Created() }
func (o osInfo) IsDir() bool        { return o.f.Type == "folder" }
func (o osInfo) Mode() os.FileMode {
	mode := os.FileMode(666) // I guess this is about right?
	if o.f.Type == "folder" {
		mode |= os.ModeDir
	}
	return mode
}
func (o osInfo) Sys() interface{} { return o.f }

// ToOSInfo returns a reference to f
// inside a thin wrapper that implements
// the os.FileInfo interface.
func (f *FileInfo) ToOSInfo() os.FileInfo {
	return osInfo{f}
}

// File is a complete file, including metadata.
type File struct {
	FileInfo

	// Body is the body of the file.
	// Typically, Body is simply whatever
	// is returned in http.Request.Body.
	Body io.ReadCloser
}

// make a download GET request to the given URI
func (c *Client) get(uri, query string) (*File, error) {
again:
	if !c.has(CapReadFiles) {
		return nil, fmt.Errorf("capabilities %q insufficient for reading files", c.Key.Cap.String())
	}
	seq := c.mut.rlock()
	auth := c.mut.auth
	host := c.mut.dl
	c.mut.runlock()
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Host:     host,
			Path:     uri,
			Scheme:   "https",
			RawQuery: query,
		},
		Header: make(http.Header),
	}
	req.Header.Set("Authorization", auth)
	res, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 && res.StatusCode != 206 {
		e := &Error{Op: "GET " + req.URL.String(), Status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(e)
		res.Body.Close()
		err = c.renew(res, e, seq)
		if err == nil {
			goto again
		}
		return nil, err
	}

	h := res.Header
	name, err := url.PathUnescape(h.Get("X-Bz-File-Name"))
	if err != nil {
		return nil, err
	}

	var info map[string]string
	for k, vals := range h {
		if strings.HasPrefix(k, "X-Bz-Info-") {
			if info == nil {
				info = make(map[string]string)
			}
			info[strings.TrimPrefix(k, "X-Bz-Info-")] = strings.Join(vals, ", ")
		}
	}

	var created int64
	ts := h.Get("X-Bz-Upload-Timestamp")
	if i, err := strconv.ParseInt(ts, 10, 64); err == nil {
		created = i
	}

	f := &File{
		FileInfo: FileInfo{
			ContentType: h.Get("Content-Type"),
			Size:        res.ContentLength,
			Name:        name,
			ID:          h.Get("X-Bz-File-Id"),
			Extra:       info,
			Timestamp:   created,
		},
		Body: res.Body,
	}
	return f, nil
}

// Get gets a File from a (bucket, filename) pair.
// It is the caller's responsibility to close File.Body
// after using the data.
func (c *Client) Get(bucket, name string) (*File, error) {
	f, err := c.get("/file/"+url.PathEscape(bucket)+"/"+url.PathEscape(name), "")
	if f != nil {
		f.Bucket = bucket
	}
	return f, err
}

// GetID gets a file by its ID.
// It is the caller's responsibility to close File.Body
// after using the data.
func (c *Client) GetID(id string) (*File, error) {
	return c.get("/b2api/v1/b2_download_file_by_id", "fileId="+url.QueryEscape(id))
}

type Bucket struct {
	ID   string `json:"bucketId"`
	Name string `json:"bucketName"`
	Type string `json:"bucketType"` // "allPrivate" "allPublic" "snapshot"
}

// Buckets lists all of the buckets in the account matching the given type(s).
// If no types are given, all buckets are returned.
func (c *Client) Buckets(types ...string) ([]Bucket, error) {
	if !c.has(CapListBuckets) {
		return nil, fmt.Errorf("cap %q cannot list buckets", c.Key.Cap.String())
	}
	if len(types) == 0 {
		types = []string{"allPrivate", "allPublic", "snapshot"}
	}
	req := struct {
		ID    string   `json:"accountId"`
		Types []string `json:"bucketTypes"`
	}{c.Key.AccountID, types}
	res := struct {
		Buckets []Bucket `json:"buckets"`
	}{}
	err := c.api("b2_list_buckets", &req, &res)
	if err != nil {
		return nil, err
	}
	return res.Buckets, nil
}

// ListBucket returns up to 'max' FileInfo entries
// beginning at the given file prefix, along with the next
// prefix (lexographically) to continue listing from. If there
// are no more files left to be listed, "" is returned as the next prefix.
func (c *Client) ListBucket(bucket *Bucket, start string, max int) ([]FileInfo, string, error) {
	if !c.has(CapListFiles) {
		return nil, "", fmt.Errorf("cap %q cannot list files", c.Key.Cap.String())
	}
	// This API doesn't support more than 10000 entries
	if max > 10000 || max < 0 {
		max = 10000
	}
	req := struct {
		Bucket string `json:"bucketId"`
		Next   string `json:"startFileName"`
		Max    int    `json:"maxFileCount"`
	}{bucket.ID, start, max}
	res := struct {
		Files []FileInfo `json:"files"`
		Next  *string    `json:"nextFileName"`
	}{}
	err := c.api("b2_list_file_names", &req, &res)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if res.Next != nil {
		next = *res.Next
	}
	return res.Files, next, nil
}

// Key represents a B2 access key.
// Keys are used to produce Clients.
type Key struct {
	// Cap is the set of capabilites for the key
	Cap Capabilities `json:"capabilities"`
	// ID is b2's internal ID for the key
	ID string `json:"applicationKeyId"`
	// Name is the user-specified name for the key.
	// A name does not necessarily uniquely specify
	// a key; only an ID does.
	Name string `json:"keyName"`
	// Value is the actual value of the key.
	// Some APIs (ListKeys) do not return
	// the value of the key, so this field
	// may be empty depending upon how the
	// Key was constructed.
	Value string `json:"applicationKey"`
	// AccountID is the ID of the parent account of this key
	AccountID string `json:"accountId"`
	// RawExpires is the time (in unix time) at which
	// this key expires. A value of zero indicates
	// that the key does not have an expiration time.
	RawExpires int64 `json:"expirationTimestamp,omitempty"`
	// OnlyBucket, if not an empty string,
	// is the only bucket that this key
	// has permission to access.
	OnlyBucket string `json:"bucketId,omitempty"`
	// OnlyPrefix, if not an empty string,
	// indicates that this key can only
	// access files with names that have
	// this prefix.
	OnlyPrefix string `json:"namePrefix,omitempty"`
}

// Expires returns when the key expires,
// or the zero value of time.Time if
// the key does not have an expiration date.
func (k *Key) Expires() time.Time {
	return time.Unix(k.RawExpires, 0)
}

// ListKeys lists the keys associated with the account.
// (The client must have the CapListKeys capability.)
// If 'max' is greater than zero, it specifies the maximum
// number of keys to return. If 'start' is not "", it specifies
// the key at which to start listing (lexicographically).
// The returned values are the list of keys and the next key
// to start listing from (if the complete list of keys
// was not returned).
func (c *Client) ListKeys(start string, max int) ([]Key, string, error) {
	if !c.has(CapListKeys) {
		return nil, "", fmt.Errorf("cap %q cannot list keys", c.Key.Cap.String())
	}
	if max < 0 {
		max = 0
	} else if max > 10000 {
		max = 10000
	}
	req := struct {
		ID    string `json:"accountId"`
		Count int    `json:"maxKeyCount,omitempty"`
		Start string `json:"startApplicationKeyId,omitempty"`
	}{
		ID:    c.Key.AccountID,
		Count: max,
		Start: start,
	}
	res := struct {
		Keys []Key  `json:"keys"`
		Next string `json:"nextApplicationKeyId"`
	}{}
	err := c.api("b2_list_keys", &req, &res)
	if err != nil {
		return nil, "", err
	}
	return res.Keys, res.Next, nil
}

// NewKey creates a new key.
// key.Name, key.Cap, key.OnlyBucket, and key.OnlyPrefix
// are used to identify the key name, capabilities,
// and bucket and filename restrictions, respectively.
// If 'valid' is non-zero, it identifies how long
// the key should remain valid.
// If NewKey returns without an error, then 'key'
// can be used to construct a client with the new
// capabilities with (*Key).Authorize(...)
func (c *Client) NewKey(key *Key, valid time.Duration) error {
	if !c.has(CapWriteKeys) {
		return fmt.Errorf("cap %q cannot create keys", c.Key.Cap.String())
	}
	req := struct {
		ID     string       `json:"accountId"`
		Cap    Capabilities `json:"capabilities"`
		Name   string       `json:"keyName"`
		Valid  int64        `json:"validDurationInSeconds,omitempty"`
		Bucket string       `json:"bucketId,omitempty"`
		Prefix string       `json:"namePrefix,omitempty"`
	}{
		ID:     c.Key.AccountID,
		Cap:    key.Cap,
		Name:   key.Name,
		Valid:  int64(valid / time.Second),
		Bucket: key.OnlyBucket,
		Prefix: key.OnlyPrefix,
	}

	return c.api("b2_create_key", &req, key)
}

// acquire an upload url and auth token for a bucket
func (c *Client) upload(bucketID string) (*urlentry, error) {
	if !c.has(CapWriteFiles) {
		return nil, fmt.Errorf("cap %q cannot write files", c.Key.Cap.String())
	}

	// see if we can grab a recently-used
	// upload authorization from the cache...
	e := c.uploads.get(bucketID)
	if e != nil {
		return e, nil
	}

	req := struct {
		Bucket string `json:"bucketId"`
	}{Bucket: bucketID}
	res := struct {
		Bucket string `json:"bucketId"`
		URL    string `json:"uploadUrl"`
		Token  string `json:"authorizationToken"`
	}{}
	err := c.api("b2_get_upload_url", &req, &res)
	if err != nil {
		return nil, err
	}
	if res.Bucket != bucketID {
		panic("b2 is misbehaving badly")
	}
	return &urlentry{
		orig: time.Now(),
		url:  res.URL,
		auth: res.Token,
	}, nil
}

// Upload uploads a file to a bucket.
// Upload uses f.Name as the file name,
// f.ContentType for the content type,
// and f.Size for the file size.
// f.Body should point to an io.ReadCloser
// that will read exactly f.Size bytes until EOF.
// f.Body.Close() will be called after the HTTP request is made.
// (Callers who wish to avoid closing the underlying
// stream may choose to wrap f.Body with an ioutil.NopCloser.)
//
// NOTE: if f.Body is a type for which net/http.NewRequest
// provides an implementation of http.Request.GetBody,
// then requests that fail on expired authorization tokens
// will be re-tried if Client.AutoRetry is set.
// Otherwise, it is the caller's responsibility to
// re-populate f.Body and call Upload again.
// See documentation for http.NewRequest and b2.Error.Temporary.
//
// BUGS: Unfortunately, based on Backblaze's documentation,
// there are a variety of circumstances under which an upload can fail.
// Clients should handle return values of type *b2.Error for which
// (*b2.Error).Temporary() returns true.
// Backblaze's own documentation suggests that upload failures
// are frequent and unpredictable.
func (c *Client) Upload(b *Bucket, f *File) error {
	if len(f.Extra) > 10 {
		return fmt.Errorf("b2 only allows 10 X-Bz-Info* headers; have %d", len(f.Extra))
	}
	body := f.Body
again:
	token, err := c.upload(b.ID)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", token.url, body)
	if err != nil {
		return fmt.Errorf("b2 returned a bad URL: %s", err)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing insecure scheme %q", req.URL.Scheme)
	}
	req.Header.Set("Authorization", token.auth)
	req.Header.Set("X-Bz-File-Name", url.PathEscape(f.Name))

	// There is simply no reason to send a SHA1 here.
	// HTTPS provides an even stronger integrity guarantee
	// than SHA1, and we insist on https uploads.
	// Computing a SHA1 here would be redundant and slow.
	req.Header.Set("X-Bz-Content-Sha1", "do_not_verify")
	if f.ContentType != "" {
		req.Header.Set("Content-Type", f.ContentType)
	} else {
		req.Header.Set("Content-Type", "b2/x-auto")
	}
	req.Header.Set("Content-Length", strconv.FormatInt(f.Size, 10))
	req.ContentLength = f.Size
	for k, v := range f.Extra {
		req.Header.Set("X-Bz-Info-"+url.PathEscape(k), url.PathEscape(v))
	}

	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		e := &Error{Op: "b2_upload_file", Status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(e)
		if req.GetBody == nil || !c.AutoRetry {
			return e
		}
		if e.Temporary() {
			body, err = req.GetBody()
			if err != nil {
				return err
			}
			goto again
		}
		e.Op = "b2_upload_file"
		return e
	}

	resinfo := struct {
		Account       string          `json:"accountId"`
		Action        string          `json:"action"`
		BucketID      string          `json:"bucketId"`
		ContentLength int64           `json:"contentLength"`
		ContentSHA    string          `json:"contentSha1"`
		ContentType   string          `json:"contentType"`
		ID            string          `json:"fileId"`
		Info          json.RawMessage `json:"fileInfo"`
		Name          string          `json:"fileName"`
		Modtime       int64           `json:"uploadTimestamp"`
	}{}
	err = json.NewDecoder(res.Body).Decode(&resinfo)
	if err != nil {
		return err
	}

	c.uploads.put(b.ID, token)

	// TODO: incorporate any other file info?
	f.ID = resinfo.ID
	f.Timestamp = resinfo.Modtime

	return nil
}
