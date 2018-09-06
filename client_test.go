package b2

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t(req)
}

func TestAuthorize(t *testing.T) {
	const wantpass = "pass"
	const wantuser = "username"

	rt := func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" {
			t.Errorf("unexpected method %q", req.Method)
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
			"apiUrl": "api-host.api-sub.backblaze.com"
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
	if client.URL.API != "api-host.api-sub.backblaze.com" {
		t.Errorf("bad api url: %s", client.URL.API)
	}

}
