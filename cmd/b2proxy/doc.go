// command b2proxy
// is a proxy server for a Backblaze B2 bucket.
//
// The b2proxy server is intended to make it
// easier to serve static content out of a
// backblaze bucket. The server understands
// HTTP semantics like CORS and Cache-Control
// headers, so sticking an HTTP cache in
// front of b2proxy should "just work."
//
// Backblaze has a rather complex API
// and a complex set of billing rules.
// (For instance, a HEAD request on a file
// is still billed as if the whole file was
// downloaded.) The purpose of this proxy
// is to try to make it easier, simpler,
// and more predictable to serve static
// content out of B2. Since B2's bandwidth
// is still relatively expensive, and
// because B2's time-to-first-byte latencies
// are large (on the order of 500ms), you
// will likely want to stick a proper caching
// HTTP server in front of b2proxy.
//
// In order to efficiently handle HEAD requests,
// CORS preflights, etc., b2proxy always holds
// the metadata for every file in the bucket
// in memory. It periodically re-synchronizes
// its metadata cache against the actual
// contents of the bucket. The server always
// fetches files by ID rather than by name,
// so the server effectively serves a snapshot
// of the bucket from the last time it
// inspected the bucket.
//
// The b2proxy server is configured
// using a JSON config file identified
// with the '-c' command-line flag.
// (Run 'go doc b2proxy.Config' for
// documentation on the necessary
// configuration.)
package main
