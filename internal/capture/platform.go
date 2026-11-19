package capture

// Platform contract. Every supported OS (capture_linux.go, capture_darwin.go,
// capture_windows.go) must provide these symbols. The assignments turn a
// missing or mismatching implementation into a compile error pointing here;
// `make vet` type-checks all release platforms, and TestOpen exercises the
// implementation at runtime on each OS.
var (
	_ func(iface string, port uint16) ([]reader, error) = open
	_ int                                               = readBufferSize
)
