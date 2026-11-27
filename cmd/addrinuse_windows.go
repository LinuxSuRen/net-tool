//go:build windows

package cmd

import (
	"errors"
	"syscall"
)

// wsaEADDRINUSE is the WinSock error for an occupied address. Go invents a
// different syscall.EADDRINUSE value on Windows, so matching that constant
// does not work for net.Listen failures.
const wsaEADDRINUSE = syscall.Errno(10048)

// isAddrInUse reports whether a listen failure was caused by the port being
// occupied, as opposed to a bad address or a permission problem.
func isAddrInUse(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaEADDRINUSE
}
