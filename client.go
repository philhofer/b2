package b2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

// Client represents a client to the Backblaze b2 API.
// Typically, a client should be constructed using Authorize().
type Client struct {
	AccountID string
	AuthToken string
	URL       struct {
		API      string
		Download string
	}
	// Cap is the set of capabilities associated
	// with the current AuthToken. As a special case,
	// a zero Cap means unknown capabilities.
	Cap      Capabilities

	// PartSize is the recommended part size for
	// file uploads.
	PartSize int64

	// MinPartSize is the smallest allowed part size
	// for file uploads.
	MinPartSize int64

	// Client is the http.Client used to make requests.
	// If Client is nil, then http.DefaultClient is used.
	Client *http.Client
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

func do(op string, req *http.Request) (*http.Response, error) {
	res, err := http.DefaultClient.Do(req)
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
func Authorize(keyID, key string) (*Client, error) {
	req, err := http.NewRequest("GET", "https://api.backblazeb2.com/b2api/v1/b2_authorize_account", nil)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth(keyID, key)
	res, err := do("b2_authorize_account", req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	val := struct {
		ID          string       `json:"accountId"`
		Auth        string       `json:"authorizationToken"`
		Cap         Capabilities `json:"capabilities"`
		URL         string       `json:"apiUrl"`
		Download    string       `json:"downloadUrl"`
		PartSize    int64        `json:"recommendedPartSize"`
		MinPartSize int64        `json:"absoluteMinimumPartSize"`
	}{}

	err = json.NewDecoder(res.Body).Decode(&val)
	if err != nil {
		return nil, err
	}

	c := &Client{
		AccountID:   val.ID,
		AuthToken:   val.Auth,
		Cap:         val.Cap,
		PartSize:    val.PartSize,
		MinPartSize: val.MinPartSize,
		Client:      http.DefaultClient,
	}
	c.URL.API = val.URL
	c.URL.Download = val.Download
	return c, nil
}

func (c *Client) http() *http.Client {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	return c.Client
}

func (c *Client) has(cap Capabilities) bool {
	return c.Cap&cap == cap
}

func (c *Client) api(op string, body, res interface{}) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.URL.API+"/b2api/v1/"+op, bytes.NewReader(buf))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", c.AuthToken)
	hres, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer hres.Body.Close()
	d := json.NewDecoder(hres.Body)
	if hres.StatusCode != 200 {
		e := &Error{Op: op}
		d.Decode(e)
		return e
	}
	return d.Decode(res)
}

// FileInfo represents information about a file.
type FileInfo struct {
	Type        string            `json:"action"` // "upload" or "folder"
	ContentType string            `json:"contentType"` // ContentType is the value of the Content-Type HTTP header
	ID          string            `json:"fileId"` // ID is the file ID
	Name        string            `json:"fileName"` // Name is the file name
	Bucket      string            `json:"-"` // Bucket is the bucket containing the file
	Size        int64             `json:"size"` // Size is the size of the file
	Extra       map[string]string `json:"fileInfo,omitempty"` // Extra contains extra file metadata
	Timestamp   int64             `json:"uploadTimestamp"` // Timestamp, unix milliseconds
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
func (c *Client) get(uri string) (*File, error) {
	if c.Cap != 0 && !c.has(CapReadFiles) {
		return nil, fmt.Errorf("capabilities %q insufficient for reading files", c.Cap.String())
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		panic(err)
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
		return nil, e
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
	return c.get(c.URL.Download+"/file/"+bucket+"/"+name)
}

// GetID gets a file by its ID.
// It is the caller's responsibility to close File.Body
// after using the data.
func (c *Client) GetID(id string) (*File, error) {
	return c.get(c.URL.Download+"/b2api/v1/b2_download_file_by_id?fileId="+url.QueryEscape(id))
}

type Bucket struct {
	ID string   `json:"bucketId"`
	Name string `json:"bucketName"`
	Type string `json:"bucketType"` // "allPrivate" "allPublic" "snapshot"
}

// Buckets lists all of the buckets in the account matching the given type(s).
// If no types are given, all buckets are returned.
func (c *Client) Buckets(types ...string) ([]Bucket, error) {
	if len(types) == 0 {
		types = []string{"allPrivate", "allPublic", "snapshot"}
	}
	req := struct{
		ID string `json:"accountId"`
		Types []string `json:"bucketTypes"`
	}{c.AccountID, types}
	res := struct{
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
	// This API doesn't support more than 10000 entries
	if max > 10000 || max < 0 {
		max = 10000
	}
	req := struct{
		Bucket string `json:"bucketId"`
	}{bucket.ID}
	res := struct{
		Files []FileInfo `json:"files"`
		Next *string `json:"nextFileName"`
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
