package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dchest/siphash"
	"github.com/philhofer/b2"
)

type table struct {
	toplevel [8]hbucket
}

type hbucket struct {
	lock    sync.Mutex
	entries map[string]*cacheinfo
}

type cacheinfo struct {
	info    b2.FileInfo
	etag    string
	headers [][2]string
}

func (t *table) init() {
	for i := range t.toplevel {
		t.toplevel[i].entries = make(map[string]*cacheinfo)
	}
}

// siphash seeds; generated at start-up
var seed0, seed1 uint64

func init() {
	var buf [16]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	seed0 = binary.LittleEndian.Uint64(buf[:8])
	seed1 = binary.LittleEndian.Uint64(buf[8:])
}

func (t *table) sort() []*b2.FileInfo {
	var out []*b2.FileInfo
	for i := range t.toplevel {
		h := &t.toplevel[i]
		h.lock.Lock()
		for _, v := range h.entries {
			out = append(out, &v.info)
		}
		h.lock.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (t *table) bucket(name string) *hbucket {
	return &t.toplevel[siphash.Hash(seed0, seed1, []byte(name))&7]
}

func (t *table) update(meta *b2.FileInfo) {
	h := t.bucket(meta.Name)
	headers := fiheader(meta)
	h.lock.Lock()
	e, ok := h.entries[meta.Name]
	if !ok {
		e = new(cacheinfo)
		h.entries[meta.Name] = e
	}
	e.info = *meta
	// don't save Extra; we don't use it and it might be large
	e.info.Extra = nil

	e.etag = etag(meta.ID)
	e.headers = headers
	h.lock.Unlock()
}

func (t *table) get(name string, out *cacheinfo) bool {
	var e *cacheinfo
	var ok bool
	h := t.bucket(name)
	h.lock.Lock()
	e, ok = h.entries[name]
	if ok {
		*out = *e
	}
	h.lock.Unlock()
	return ok
}

func (t *table) evict(info *cacheinfo) {
	h := t.bucket(info.info.Name)
	h.lock.Lock()
	e, ok := h.entries[info.info.Name]
	if ok && e.info.ID == info.info.ID {
		delete(h.entries, info.info.Name)
	}
	h.lock.Unlock()
}

// generate an ETag that represents the file ID,
// but don't use the file version (or an unseeded hash of it),
// since leaking the actual file ID might be problematic
// from a security perspective
func etag(id string) string {
	return strconv.FormatUint(siphash.Hash(seed0, seed1, []byte(id)), 36)
}

func fiheader(fi *b2.FileInfo) [][2]string {
	const CustomHeaderPrefix = "HTTP-"

	out := [][2]string{
		{"Content-Type", fi.ContentType},
		{"Content-Length", strconv.FormatInt(fi.Size, 10)},
		{"ETag", etag(fi.ID)},
		{"Last-Modified", fi.Created().Format(time.RFC1123)},
	}
	for k, v := range fi.Extra {
		l := len(k)
		s := strings.TrimPrefix(k, CustomHeaderPrefix)
		if len(s) == l-len(CustomHeaderPrefix) {
			out = append(out, [2]string{s, v})
		}
	}
	return out
}

func (s *server) loadBucket() (*b2.Bucket, error) {
	if s.conf.BucketID != "" {
		return &b2.Bucket{
			ID:   s.conf.BucketID,
			Name: s.conf.Bucket,
		}, nil
	}

	// Weird B2 idiosyncracy:
	// We want to list the named bucket
	// in the configuration, but that requires
	// a bucket ID, and the only way to get that
	// when you just have a bucket name is
	// to list the buckets and match against
	// the name. As a consequence, if the config
	// doesn't contain the bucket ID, we need
	// CapListBuckets.
	if s.b2c.Key.Cap&b2.CapListBuckets == 0 {
		return nil, fmt.Errorf("bucket name %q provided w/o ID; need CapListBuckets to find bucket ID", s.conf.Bucket)
	}
	buckets, err := s.b2c.Buckets()
	if err != nil {
		return nil, err
	}

	for i := range buckets {
		if buckets[i].Name == s.conf.Bucket {
			s.conf.BucketID = buckets[i].ID
			return &buckets[i], nil
		}
	}
	return nil, fmt.Errorf("no such bucket %q", s.conf.Bucket)
}

// populate updates the metadata cache
func (s *server) populate() error {
	bucket, err := s.loadBucket()
	if err != nil {
		return err
	}
	prefix := ""
	present := make(map[string]struct{})
	for {
		fis, next, err := s.b2c.ListBucket(bucket, prefix, 100)
		if err != nil {
			return err
		}

		for i := range fis {
			if fis[i].Type != "upload" {
				continue
			}
			present[fis[i].Name] = struct{}{}
			s.meta.update(&fis[i])
		}

		if next == "" {
			break
		}
		prefix = next
	}

	// now delete stuff that isn't present any more
	for i := range s.meta.toplevel {
		b := &s.meta.toplevel[i]
		b.lock.Lock()

		for k := range b.entries {
			_, ok := present[k]
			if !ok {
				delete(b.entries, k)
			}
		}

		b.lock.Unlock()
	}

	return nil
}
