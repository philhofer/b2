package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/philhofer/b2"
)

var conffile string

func init() {
	flag.StringVar(&conffile, "c", "config.json", "path to config file")
}

type server struct {
	b2c      *b2.Client
	conf     Config
	meta     table
	host     string // host part of Config.LocalAddress
	bucketID string // ID of conf.Bucket
}

func (s *server) auth() error {
	var err error
	s.b2c, err = b2.Authorize(s.conf.B2KeyID, s.conf.B2Key)
	return err
}

func (s *server) allowsOrigin(origin string) bool {
	if len(s.conf.AllowedOrigins) == 0 {
		return true
	}
	for i := range s.conf.AllowedOrigins {
		if s.conf.AllowedOrigins[i] == "*" ||
			s.conf.AllowedOrigins[i] == origin {
			return true
		}
	}
	return false
}

func (s *server) options(req *http.Request, w http.ResponseWriter) {
	origin := req.Header.Get("Origin")
	if !s.allowsOrigin(origin) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	h := w.Header()
	origins := s.conf.AllowedOrigins

	// The allowed methods and headers are
	// not going to change. Allow browsers
	// to cache these results for a long time.
	h.Set("Access-Control-Max-Age", "86400")
	h["Access-Control-Allow-Methods"] = origins
	h["Access-Control-Allow-Methods"] = []string{"GET", "HEAD"}
	w.WriteHeader(200)
}

func errconv(w http.ResponseWriter, err error) {
	if b2err, ok := err.(*b2.Error); ok {
		w.WriteHeader(b2err.Status)
		io.WriteString(w, b2err.Message)
		return
	}
	if _, ok := err.(net.Error); ok {
		w.WriteHeader(502)
		io.WriteString(w, "bad gateway")
		return
	}
	log.Printf("error: %s", err)
	w.WriteHeader(500)
	io.WriteString(w, "internal server error")
}

func sethdr(w http.ResponseWriter, info *cacheinfo) {
	h := w.Header()
	for i := range info.headers {
		h.Set(info.headers[i][0], info.headers[i][1])
	}
}

func (s *server) loadconf() {
	s.conf = DefaultConfig

	f, err := os.Open(conffile)
	if err != nil {
		log.Fatalf("couldn't open config: %s", err)
	}
	defer f.Close()

	err = json.NewDecoder(f).Decode(&s.conf)
	if err != nil {
		log.Fatalf("couldn't parse config: %s", err)
	}

	err = s.conf.Validate()
	if err != nil {
		log.Fatalf("bad config: %s", err)
	}
}

func (s *server) earlyOut(w http.ResponseWriter, headers http.Header, info *cacheinfo) bool {
	if match := headers.Get("If-None-Match"); match != "" {
		if match != info.etag {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	if match := headers.Get("If-Modified-Since"); match != "" {
		after, err := time.Parse(time.RFC1123, match)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		if after.After(info.info.Created()) {
			w.Header().Set("Last-Modified", info.info.Created().Format(time.RFC1123))
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	return false
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	if len(req.URL.Path) <= 1 { // ?
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if req.URL.Path[0] == '/' {
		req.URL.Path = req.URL.Path[1:]
	}
	var info cacheinfo
	if !s.meta.get(req.URL.Path, &info) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch req.Method {
	case "GET":
		if s.earlyOut(w, req.Header, &info) {
			return
		}
		// TODO: support Range headers; they
		// can be forwarded directly to B2 (in principle...)
		f, err := s.b2c.GetID(info.info.ID)
		if err != nil {
			errconv(w, err)
			return
		}
		defer f.Body.Close()
		sethdr(w, &info)
		w.WriteHeader(200)
		io.Copy(w, f.Body)
	case "HEAD":
		if s.earlyOut(w, req.Header, &info) {
			return
		}
		sethdr(w, &info)
		w.WriteHeader(200)
	case "OPTIONS":
		s.options(req, w)
	default:
		h := w.Header()
		h["Allow"] = []string{"GET", "HEAD", "OPTIONS"}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) refresh() {
	for {
		time.Sleep(s.conf.RefreshInterval)
		err := s.populate()
		if err != nil {
			log.Printf("couldn't fill metadata cache: %s", err)
		}
	}
}

func main() {
	flag.Parse()
	s := new(server)
	s.meta.init()
	s.loadconf()

	log.Println("authenticating with B2...")
	if err := s.auth(); err != nil {
		log.Fatalf("couldn't authenticate with B2: %s", err)
	}

	log.Println("downloading and indexing metadata...")
	if err := s.populate(); err != nil {
		log.Fatal("couldn't fill metadata cache: %s", err)
	}

	log.Printf("beginning server on %s", s.conf.LocalAddress)
	go s.refresh()

	// use http.ServeMux for matching 'Host: '
	mux := http.NewServeMux()
	mux.Handle(s.conf.host+"/", s)

	if s.conf.useTLS {
		log.Fatal(http.ListenAndServeTLS(s.conf.LocalAddress, s.conf.CertFile, s.conf.PemFile, mux))
	} else {
		log.Fatal(http.ListenAndServe(s.conf.LocalAddress, mux))
	}
}
