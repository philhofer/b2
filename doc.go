// package b2
// is a client library for Backblaze B2.
//
// This library was written to support
// b2proxy, but you can use it independently
// if you'd like.
//
// Since this library supports a specific
// application, it does not wrap the
// complete set of B2 APIs.
// Over time we may add support for more
// B2 APIs, but it is not the intention
// of this library to support the
// 'kitchen sink' of B2 functionality.
// Instead, we'd like to keep the library
// surface-area small, and try to paper over
// as many B2 API idiosyncracies as we
// reasonably can.
//
// Calls to the B2 API are mediated through
// the b2.Client type, which wraps a session
// key and other ephemeral information necessary
// to communicate with the API. To construct
// a b2.Client, you need a b2.Key.
// (You can produce a key on the backblaze
// B2 management interface.)
//
//	key := b2.Key{ID: "your-key-ID-here", Value: "your-key-here"}
//	client, err := key.Authorize(nil)
//	if err != nil {
//	  fmt.Println("couldn't authorize with B2:", err)
//	}
//
// Keep in mind that B2 is an object store,
// not a filesystem, so its CRUD semantics
// do not map neatly to filesystem operations.
// B2 objects have opaque IDs that uniquely
// identify them; object names are merely
// a tool for indexing file IDs.
// Consequently, there are two ways to get a file:
//
//	file, err := client.GetID("file-id-here")
//
// and
//
//	bucket := b2.Bucket{ ... }
//	file, err := client.Get(bucket, "file-name-here")
//
// Buckets, like files, have both names and IDs, and
// you'll need a bucket ID (not a name) in order to use
// the regular (*Client).Get API.
package b2
