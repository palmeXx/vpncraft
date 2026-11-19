//go:build !linux && !darwin && !windows

package netutil

import "errors"

// Routes is not implemented on this platform.
func Routes() ([]Route, error) {
	return nil, errors.ErrUnsupported
}
