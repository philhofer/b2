package b2

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCapabilitesText(t *testing.T) {
	tbl := []struct {
		cap Capabilities
		str string
	}{
		{CapReadFiles, "readFiles"},
		{CapReadFiles | CapWriteFiles, "readFiles,writeFiles"},
		{CapListKeys | CapWriteKeys | CapListBuckets | CapReadFiles | CapWriteFiles,
			"listKeys,writeKeys,listBuckets,readFiles,writeFiles"},
	}

	for i := range tbl {
		tc := &tbl[i]
		out := tc.cap.String()
		if out != tc.str {
			t.Errorf("want %q, got %q", tc.str, out)
		}
		buf, err := json.Marshal(tc.cap)
		if err != nil {
			t.Errorf("failed to marshal %q: %s", tc.str, err)
		}
		var sep []string
		err = json.Unmarshal(buf, &sep)
		if err != nil {
			t.Errorf("couldn't unmarshal %s %s", buf, err)
		}
		csep := strings.Split(out, ",")
		if !reflect.DeepEqual(sep, csep) {
			t.Errorf("%v not equal to %v", sep, csep)
		}
	}
}

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
			"allowed": {"capabilities": ["listBuckets","readFiles","writeFiles"]},
			"authorizationToken": "the-auth-token"
		}`)
		return &http.Response{
			Body:       ioutil.NopCloser(retbody),
			StatusCode: 200,
		}, nil
	}
	http.DefaultClient.Transport = transport(rt)

	client, err := (&Key{ID: wantuser, Value: wantpass}).Authorize(nil)
	if err != nil {
		t.Errorf("authorize: %s", err)
	}
	if client.Key.AccountID != "the-id" {
		t.Errorf("bad account id: %s", client.Key.AccountID)
	}
	if client.mut.auth != "the-auth-token" {
		t.Error("bad auth token")
	}
	if client.mut.api != "api-host.api-sub.backblaze.com" {
		t.Errorf("bad api url: %s", client.mut.api)
	}
	if client.mut.dl != "data-host.data-sub.backblaze.com" {
		t.Errorf("bad download url: %s", client.mut.dl)
	}
	if client.Key.Cap != CapListBuckets|CapReadFiles|CapWriteFiles {
		t.Errorf("bad capabilities: %v", client.Key.Cap)
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
		retbody := strings.NewReader(`{
			"buckets": [{"bucketId":"bucket-id","bucketName":"bucket-name","bucketType":"allPrivate"}]
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

	wantauth := client.mut.auth
	wanthost := client.mut.dl
	now := time.Now().Unix()
	rt = func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/file/"+bucket.Name+"/file-name" {
			t.Errorf("unexpected path: %s", req.URL.Path)
		}
		if req.URL.Host != wanthost {
			t.Error("bad host in request", req.URL.Host, wanthost)
		}
		if req.Header.Get("Authorization") != wantauth {
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

	// test the re-authorization case:
	// we try to get a file, which causes a 401 to be
	// returned, which should trigger a re-auth and
	// another GET of the file with the new auth token
	client.AutoRenew = true
	realget := rt
	expire := func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" {
			t.Error("unexpected request method", req.Method)
		}
		if req.Header.Get("Authorization") != wantauth {
			t.Error("unexpected request Authorization header")
		}
		if req.URL.Host != wanthost {
			t.Error("bad host in request")
		}
		return &http.Response{
			Body:       ioutil.NopCloser(strings.NewReader(`{"code": "bad_auth_token"}`)),
			StatusCode: 401,
		}, nil
	}
	auth := func(req *http.Request) (*http.Response, error) {
		// it's not clear from B2's documentation if we should
		// re-authorize using the old API url, or if we should
		// authorize like the initial authorization...
		// empirically, this seems to work
		if req.URL.Host != "api.backblazeb2.com" {
			t.Error("request not to api host...?", req.URL.Host)
		}
		wantauth = "a-second-auth-token"
		wanthost = "other-host.dl.backblaze.com"
		return &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(`{
				"accountId": "account-id",
				"downloadUrl": "https://other-host.dl.backblaze.com",
				"apiUrl": "https://other-host.api.backblaze.com",
				"authorizationToken": "a-second-auth-token"
			}`)),
			StatusCode: 200,
		}, nil
	}

	count := 0
	http.DefaultClient.Transport = transport(func(req *http.Request) (*http.Response, error) {
		c := count
		count++
		switch c {
		case 0:
			return expire(req)
		case 1:
			return auth(req)
		default:
			return realget(req)
		}
	})

	f, err = client.Get(bucket.Name, "file-name")
	if err != nil {
		t.Fatal(err)
	}
	f.Body.Close()
}
