package netutil

// Platform contract. Every OS (routes_linux.go, routes_darwin.go,
// routes_windows.go, routes_other.go) must provide Routes. The assignment turns
// a missing or mismatching implementation into a compile error pointing here;
// `make vet` type-checks all release platforms, and TestRoutes decodes the
// real routing table on each OS.
var _ func() ([]Route, error) = Routes
