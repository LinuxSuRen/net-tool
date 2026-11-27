//go:build !windows

package cmd

import (
	"errors"
	"syscall"
)

// isAddrInUse reports whether a listen failure was caused by the port being
// occupied, as opposed to a bad address or a permission problem.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
