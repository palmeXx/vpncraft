package relay

// Platform contract. Every supported OS (forwarder_unix.go,
// forwarder_windows.go) must provide openRawConn. The assignment turns a
// missing or mismatching implementation into a compile error pointing here;
// `make vet` type-checks all release platforms, and TestOpenRawConn sends a
// real packet on each OS, which catches runtime stubs such as the
// "not implemented" sendmsg of x/net on Windows.
var _ func() (rawConn, error) = openRawConn
