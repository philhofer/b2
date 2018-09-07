package b2

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t(req)
}

func TestHappyCase(t *testing.T) {
	const wantpass = "pass"
	const wantuser = "username"

	rt := func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" {
			t.Errorf("unexpected method %q", req.Method)
		}
		if req.URL.Scheme != "https" {
			t.Error("unexpected scheme", req.URL.Scheme)
		}
		if req.URL.Host != "api.backblazeb2.com" {
			t.Error("bad host", req.URL.Host)
		}
		if req.URL.Path != "/b2api/v1/b2_authorize_account" {
			t.Error("bad path", req.URL.Path)
		}
		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Fatal("no basic auth?")
		}
		if user != wantuser || pass != wantpass {
			t.Error("bad basic auth")
		}
		retbody := strings.NewReader(`{
			"accountId": "the-id",
			"apiUrl": "https://api-host.api-sub.backblaze.com",
			"downloadUrl": "https://data-host.data-sub.backblaze.com",
			"capabilities": ["listBuckets","readFiles","writeFiles"],
			"authorizationToken": "the-auth-token"
		}`)
		return &http.Response{
			Body:       ioutil.NopCloser(retbody),
			StatusCode: 200,
		}, nil
	}
	http.DefaultClient.Transport = transport(rt)

	client, err := Authorize(wantuser, wantpass)
	if err != nil {
		t.Errorf("authorize: %s", err)
	}
	if client.AccountID != "the-id" {
		t.Errorf("bad account id: %s", client.AccountID)
	}
	if client.AuthToken != "the-auth-token" {
		t.Error("bad auth token")
	}
	if client.URL.API != "https://api-host.api-sub.backblaze.com" {
		t.Errorf("bad api url: %s", client.URL.API)
	}
	if client.URL.Download != "https://data-host.data-sub.backblaze.com" {
		t.Errorf("bad download url: %s", client.URL.Download)
	}
	if client.Cap != CapListBuckets|CapReadFiles|CapWriteFiles {
		t.Errorf("bad capabilities: %v", client.Cap)
	}

	rt = func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" {
			t.Errorf("unexpected scheme: %s", req.URL.Scheme)
		}
		if req.URL.Host != "api-host.api-sub.backblaze.com" {
			t.Errorf("unexpected host: %s", req.URL.Host)
		}
		if req.URL.Path != "/b2api/v1/b2_list_buckets" {
			t.Errorf("unexpected path: %s", req.URL.Path)
		}
		if req.Header.Get("Authorization") != "the-auth-token" {
			t.Error("missing auth token")
		}
		retbody := strings.NewReader(`{"buckets":
			[{"bucketId":"bucket-id","bucketName":"bucket-name","bucketType":"allPrivate"}]
		}`)
		return &http.Response{
			Body:       ioutil.NopCloser(retbody),
			StatusCode: 200,
		}, nil
	}
	http.DefaultClient.Transport = transport(rt)

	buckets, err := client.Buckets()
	if err != nil {
		t.Fatalf("listing buckets: %s", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket; found %d", len(buckets))
	}
	bucket := buckets[0]
	if bucket.Name != "bucket-name" {
		t.Errorf("unexpected bucket name %q", bucket.Name)
	}
	if bucket.ID != "bucket-id" {
		t.Errorf("unexpected bucket ID %q", bucket.ID)
	}
	if bucket.Type != "allPrivate" {
		t.Errorf("unexpected bucket type %q", bucket.Type)
	}

	now := time.Now().Unix()
	rt = func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/file/"+bucket.Name+"/file-name" {
			t.Errorf("unexpected path: %s", req.URL.Path)
		}
		if req.Header.Get("Authorization") != "the-auth-token" {
			t.Error("missing authorization")
		}
		h := make(http.Header)
		retstr := "the body of the file"
		h.Set("X-Bz-File-Name", "file-name")
		h.Set("X-Bz-File-Id", "file-id")
		h.Set("X-Bz-Upload-Timestamp", strconv.FormatInt(now, 10))
		h.Set("Content-Type", "text/plain")
		h.Set("X-Bz-Info-Foo", "foo")
		res := &http.Response{
			Header:     h,
			Body:       ioutil.NopCloser(strings.NewReader(retstr)),
			StatusCode: 200,
		}
		return res, nil
	}
	http.DefaultClient.Transport = transport(rt)

	f, err := client.Get(bucket.Name, "file-name")
	if err != nil {
		t.Fatalf("getting file: %s", err)
	}
	if f.Name != "file-name" {
		t.Errorf("unexpected name %s", f.Name)
	}
	if f.Timestamp != now {
		t.Error("bad file timestamp")
	}
	if f.Extra == nil || f.Extra["Foo"] != "foo" {
		t.Error("bad metadata")
	}
	if f.ContentType != "text/plain" {
		t.Error("unexpected content type", f.ContentType)
	}
	f.Body.Close()
}
