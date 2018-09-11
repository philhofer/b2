package b2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
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
	CapWriteBuckets
	CapDeleteBuckets
	CapListFiles
	CapReadFiles
	CapShareFiles
	CapWriteFiles
	CapDeleteFiles
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
	{CapWriteBuckets, "writeBuckets"},
	{CapDeleteBuckets, "deleteBuckets"},
	{CapListFiles, "listFiles"},
	{CapReadFiles, "readFiles"},
	{CapShareFiles, "shareFiles"},
	{CapWriteFiles, "writeFiles"},
	{CapDeleteFiles, "deleteFiles"},
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
		sync.Mutex
		sync.Cond
		authorizing       bool
		authcount         int32  // authorization sequence
		api, dl           string // api and download hostnames
		partsz, minpartsz int64  // part size, min part size
		auth              string // current auth token
	}

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
	AutoRenew bool
}

// Error represents an error returned from the B2 API
type Error struct {
	Op      string `json:"-"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
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
	out.mut.authorizing = true
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
		k.Cap = val.Allowed.Cap
		k.AccountID = val.ID
		k.OnlyBucket = val.Allowed.BucketName
		k.OnlyPrefix = val.Allowed.Prefix
		dst.mut.Cond.L = &dst.mut.Mutex
		dst.Key = *k
		dst.Client = cl
	}

	dst.mut.Lock()
	defer dst.mut.Unlock()
	dst.mut.authcount++
	dst.mut.auth = val.Auth
	dst.mut.partsz = val.PartSize
	dst.mut.minpartsz = val.MinPartSize
	if !dst.mut.authorizing {
		panic("authorization race?")
	}
	dst.mut.authorizing = false
	dst.mut.Broadcast()

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
		c.Client = http.DefaultClient
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
	c.mut.Lock()
	for c.mut.authorizing {
		c.mut.Wait()
	}
	auth := c.mut.auth
	host := c.mut.api
	seq := c.mut.authcount
	c.mut.Unlock()
	req := &http.Request{
		URL: &url.URL{
			Scheme: "https",
			Host:   host,
			Path:   path,
		},
		Header:        make(http.Header),
		Method:        method,
		Body:          ioutil.NopCloser(bytes.NewReader(buf)),
		ContentLength: int64(len(buf)),
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	return req, seq
}

func (c *Client) has(cap Capabilities) bool {
	return c.Key.Cap&cap == cap
}

func (c *Client) renew(inerr *Error, code int, seq int32) error {
	if !c.AutoRenew || code != 401 {
		return inerr
	}
	if inerr.Code != "expired_auth_token" &&
		inerr.Code != "bad_auth_token" {
		return inerr
	}
	// the logic here gets a litte tricky, because
	// we'd really like to avoid a 'thundering herd'
	// of auth requests if a bunch of goroutines are using
	// the client concurrently and the auth token expires;
	// we limit the client to one auth request and force
	// the other goroutines to wait for it to complete
	c.mut.Lock()
	if c.mut.authorizing {
		for c.mut.authorizing {
			c.mut.Wait()
		}
	} else if c.mut.authcount > seq {
		// in the time we spent waiting for a response,
		// another goroutine already got a new auth token
		c.mut.Unlock()
		return nil
	}
	c.mut.authorizing = true
	c.mut.Unlock()
	return c.Key.authorize(c.Client, c, false)
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
		e := &Error{Op: op}
		d.Decode(e)
		err = c.renew(e, hres.StatusCode, seq)
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
	c.mut.Lock()
	for c.mut.authorizing {
		c.mut.Wait()
	}
	seq := c.mut.authcount
	auth := c.mut.auth
	host := c.mut.dl
	c.mut.Unlock()
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
		err = c.renew(e, res.StatusCode, seq)
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
	}{bucket.ID}
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
