package main

import (
	"flag"
	"fmt"
	"github.com/philhofer/b2"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "    b2 get <bucket> <file>")
	fmt.Fprintln(os.Stderr, "       newkey <name> <caps> <ttl>")
	fmt.Fprintln(os.Stderr, "       keys")
	fmt.Fprintln(os.Stderr, "       list <bucket>")
	fmt.Fprintln(os.Stderr, "       put <bucket> <file...>")
	fmt.Fprintln(os.Stderr, "       sync <bucket> <file...>")
	fmt.Fprintln(os.Stderr, "       buckets")
	fmt.Fprintln(os.Stderr, "       caps")
	os.Exit(1)
}

var (
	kid     string
	key     string
	verbose bool

	lastname   string
	lastbucket *b2.Bucket
	lastauth   *b2.Client
)

func init() {
	flag.StringVar(&kid, "i", os.Getenv("B2_KEY_ID"), "B2 key ID (B2_KEY_ID)")
	flag.StringVar(&key, "k", os.Getenv("B2_KEY"), "B2 key (B2_KEY)")
	flag.BoolVar(&verbose, "v", false, "be verbose")
}

func fatalln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}

func debugln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
}

func auth() *b2.Client {
	if lastauth != nil {
		return lastauth
	}
	if kid == "" || key == "" {
		fmt.Fprintln(os.Stderr, "need B2 key and key ID (-k and -i)")
		os.Exit(1)
	}
	c, err := (&b2.Key{ID: kid, Value: key}).Authorize(nil)
	if err != nil {
		fatalln(err)
	}
	if verbose {
		debugln(" > Authorize()'d successfully")
	}
	lastauth = c
	return c
}

func get(bucket, file string) {
	c := auth()
	f, err := c.Get(bucket, file)
	if err != nil {
		fatalln(err)
	}
	defer f.Body.Close()
	_, err = io.Copy(os.Stdout, f.Body)
	if err != nil {
		fatalln(err)
	}
}

func caps() {
	fmt.Fprintln(os.Stdout, auth().Key.Cap.String())
}

func list(bucket string, subr func(fi *b2.FileInfo)) {
	c := auth()
	b := bucketnamed(bucket, c)

	prefix := ""
	for {
		// you only get charged for one transaction for
		// listing up to 1000 results, so that's the most
		// cost-effective listing multiple
		if verbose {
			debugln(" > running ListBucket, prefix =", prefix)
		}
		fis, next, err := c.ListBucket(b, prefix, 1000)
		if err != nil {
			fatalln(err)
		}
		for i := range fis {
			subr(&fis[i])
		}
		if next == "" {
			if verbose {
				debugln(" > ListBucket terminated")
			}
			break
		}
		prefix = next
	}
}

func buckets() {
	buckets, err := auth().Buckets()
	if err != nil {
		fatalln(err)
	}
	for i := range buckets {
		fmt.Printf("%s %s %s\n", buckets[i].Name, buckets[i].Type, buckets[i].ID)
	}
}

func bucketnamed(name string, c *b2.Client) *b2.Bucket {
	if name == "" {
		fatalln("emtpy bucket name")
	}
	// cache the most-recently-resolved bucket name,
	// because commands like "sync" would otherwise
	// end up resolving the bucket name twice
	if lastname != "" && name == lastname {
		return lastbucket
	}
	buckets, err := c.Buckets()
	if err != nil {
		fatalln(err)
	}
	for i := range buckets {
		if buckets[i].Name == name {
			if verbose {
				debugln(" > resolved bucket name", name)
			}
			// don't return &buckets[i],
			// because then we'd effectively leak
			// the rest of the buckets array...
			lastbucket = new(b2.Bucket)
			*lastbucket = buckets[i]
			lastname = name
			return lastbucket
		}
	}
	fatalln("no such bucket")
	return nil
}

func newkey(name, caps, ttl string) {
	c, err := b2.ParseCapabilities(caps)
	if err != nil {
		fatalln("bad capabilities:", err)
	}
	d, err := time.ParseDuration(ttl)
	if err != nil {
		fatalln("bad ttl:", err)
	}
	k := b2.Key{
		Name: name,
		Cap:  c,
	}
	err = auth().NewKey(&k, d)
	if err != nil {
		fatalln(err)
	}
	fmt.Fprintln(os.Stdout, k.ID, k.Value, k.Expires())
}

func uploadFile(c *b2.Client, b *b2.Bucket, f *os.File) error {
	ino, err := f.Stat()
	if err != nil {
		return err
	}
	if !ino.Mode().IsRegular() {
		return fmt.Errorf("can't upload file of type %s", ino.Mode())
	}

	b2f := b2.File{
		Body: ioutil.NopCloser(f),
	}
	b2f.FromOSInfo(ino)

	for {
		if verbose {
			debugln(" > beginning upload of", b2f.Name)
		}
		err = c.Upload(b, &b2f)
		if err == nil {
			break
		}
		b2e, ok := err.(*b2.Error)
		if !ok || !b2e.Temporary() {
			break
		}
		fmt.Fprintln(os.Stderr, "retry:", err)
		_, err = f.Seek(0, 0)
		if err != nil {
			break
		}
	}
	f.Close()
	if err == nil {
		fmt.Fprintln(os.Stdout, b2f.Name, b2f.ID)
	}
	return err
}

// put all the files that aren't already in the bucket
func dosync(bucket string, files []string) {
	table := make(map[string]struct{})
	for i := range files {
		table[files[i]] = struct{}{}
	}

	list(bucket, func(fi *b2.FileInfo) {
		delete(table, fi.Name)
	})

	if len(table) > 0 {
		newfiles := make([]string, 0, len(table))
		for k := range table {
			newfiles = append(newfiles, k)
		}
		put(bucket, newfiles)
	}
}

func put(bucket string, files []string) {
	c := auth()
	b := bucketnamed(bucket, c)

	concurrency := 20
	if len(files) < concurrency {
		concurrency = len(files)
	}
	wg := new(sync.WaitGroup)
	fc := make(chan string, concurrency)
	errcount := int64(0)
	wg.Add(concurrency)
	if verbose {
		debugln(" > beginning upload, #files =", len(files))
	}
	for i := 0; i < concurrency; i++ {
		go func() {
			for name := range fc {
				f, err := os.Open(name)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					atomic.AddInt64(&errcount, 1)
					continue
				}
				err = uploadFile(c, b, f)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					atomic.AddInt64(&errcount, 1)
				}
			}
			wg.Done()
		}()
	}
	for i := range files {
		fc <- files[i]
	}
	close(fc)
	if verbose {
		debugln(" > waiting for all uploads...")
	}
	wg.Wait()
	if errcount > 0 {
		os.Exit(1)
	}
}

func keys() {
	c := auth()
again:
	list, next, err := c.ListKeys("", 100)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i := range list {
		k := &list[i]
		fmt.Fprintln(os.Stdout, k.ID, k.Name, k.Cap.String())
	}
	if next != "" {
		goto again
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "get":
		if len(args) < 3 {
			usage()
		}
		get(args[1], args[2])
	case "caps":
		if len(args) < 1 {
			usage()
		}
		caps()
	case "newkey":
		if len(args) < 4 {
			usage()
		}
		newkey(args[1], args[2], args[3])
	case "buckets":
		buckets()
	case "list":
		if len(args) < 2 {
			usage()
		}
		list(args[1], func(fi *b2.FileInfo) {
			fmt.Printf("%s %s %d\n", fi.Type, fi.Name, fi.Size)
		})
	case "sync":
		if len(args) < 3 {
			usage()
		}
		dosync(args[1], args[2:])
	case "put":
		if len(args) < 3 {
			usage()
		}
		put(args[1], args[2:])
	case "keys":
		keys()
	default:
		fmt.Fprintf(os.Stderr, "unrecognized command %q\n", args[0])
		usage()
	}
}
