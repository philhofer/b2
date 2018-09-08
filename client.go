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

func (c *Capabilities) write(w io.Writer) {
	written := 0
	for i := range captable {
		if *c&captable[i].cap != 0 {
			if written != 0 {
				io.WriteString(w, ",")
			}
			io.WriteString(w, captable[i].name)
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
	c.write(&str)
	return str.String()
}

// MarshalJSON implements json.Marshaler
func (c *Capabilities) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	c.write(&buf)
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
// Typically, a client should be constructed using Authorize().
type Client struct {
	Key       *Key
	AccountID string
	AuthToken string

	Host struct {
		API      string
		Download string
	}

	// PartSize is the recommended part size for
	// file uploads.
	PartSize int64

	// MinPartSize is the smallest allowed part size
	// for file uploads.
	MinPartSize int64

	// Client is the http.Client used to make requests.
	// If Client is nil, then http.DefaultClient is used.
	Client *http.Client

	// AutoRenew determines whether or not the client
	// automatically fetches a new auth token when
	// it receives a response that the auth token
	// has expired.
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
	err := k.authorize(cl, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (k *Key) authorize(cl *http.Client, dst *Client) error {
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

	dst.Key = k
	k.Cap = val.Allowed.Cap
	k.AccountID = val.ID
	k.OnlyBucket = val.Allowed.BucketName
	k.OnlyPrefix = val.Allowed.Prefix
	dst.AccountID = val.ID
	dst.AuthToken = val.Auth
	dst.PartSize = val.PartSize
	dst.MinPartSize = val.MinPartSize
	dst.Client = cl

	var host string
	host, err = checkURL(val.URL)
	if err != nil {
		return fmt.Errorf("refusing bad api url %q", val.URL)
	}
	dst.Host.API = host
	host, err = checkURL(val.Download)
	if err != nil {
		return fmt.Errorf("refusing bad download url %q", val.Download)
	}
	dst.Host.Download = host
	return nil
}

func (c *Client) http() *http.Client {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	return c.Client
}

func (c *Client) apireq(method, path string, body interface{}) *http.Request {
	buf, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	req := &http.Request{
		URL: &url.URL{
			Scheme: "https",
			Host:   c.Host.API,
			Path:   path,
		},
		Header:        make(http.Header),
		Method:        method,
		Body:          ioutil.NopCloser(bytes.NewReader(buf)),
		ContentLength: int64(len(buf)),
	}
	req.Header.Set("Authorization", c.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (c *Client) has(cap Capabilities) bool {
	return c.Key.Cap&cap == cap
}

func (c *Client) renew(inerr *Error, code int) error {
	if !c.AutoRenew || code != 401 {
		return inerr
	}
	if inerr.Code != "expired_auth_token" &&
		inerr.Code != "bad_auth_token" {
		return inerr
	}
	return c.Key.authorize(c.Client, c)
}

func (c *Client) api(op string, body, res interface{}) error {
again:
	req := c.apireq("POST", "/b2api/v1/"+op, body)
	hres, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer hres.Body.Close()
	d := json.NewDecoder(hres.Body)
	if hres.StatusCode != 200 {
		e := &Error{Op: op}
		d.Decode(e)
		err = c.renew(e, hres.StatusCode)
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
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Host:     c.Host.Download,
			Path:     uri,
			Scheme:   "https",
			RawQuery: query,
		},
		Header: make(http.Header),
	}
	req.Header.Set("Authorization", c.AuthToken)
	res, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 && res.StatusCode != 206 {
		e := &Error{Op: "GET " + req.URL.String(), Status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(e)
		res.Body.Close()
		err = c.renew(e, res.StatusCode)
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
	f, err := c.get("/file/"+bucket+"/"+name, "")
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
	}{c.AccountID, types}
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
	Value string `json:"-"`
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
		ID:    c.AccountID,
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
