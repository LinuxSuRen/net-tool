package netconf

import (
	"errors"
	"fmt"
	"time"
)

// Wi-Fi association is asynchronous and can fail transiently (the AP is busy
// or still rejecting the previous attempt), so one join request may need a
// few tries before it really completes.
const (
	DefaultWifiAttempts = 3
	MaxWifiAttempts     = 5
)

// NormalizeWifiAttempts clamps an untrusted attempt count to a sane range;
// zero and negatives mean "use the default".
func NormalizeWifiAttempts(n int) int {
	if n <= 0 {
		return DefaultWifiAttempts
	}
	if n > MaxWifiAttempts {
		return MaxWifiAttempts
	}
	return n
}

// retryWifi calls fn until it succeeds or the attempt budget is exhausted.
// The final error keeps its stable code through %w.
func retryWifi(attempts int, delay time.Duration, fn func(attempt int) error) error {
	for i := 1; i <= attempts; i++ {
		err := fn(i)
		if err == nil {
			return nil
		}
		if i == attempts {
			if attempts > 1 {
				return fmt.Errorf("%w (after %d attempts)", err, attempts)
			}
			return err
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil // unreachable; attempts is always >= 1
}

// Stable error codes surfaced to the API/CLI; user-visible wording is
// decided by the frontend, technical detail stays in the message for logs.
const (
	CodeInvalidArgument  = "invalid_argument"
	CodeNotFound         = "not_found"
	CodeUnsupported      = "unsupported"
	CodePermissionDenied = "permission_denied"
	CodeCommandFailed    = "command_failed"
)

// Error wraps an operation failure with a stable code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func newError(code, format string, args ...any) *Error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// CodeOf returns the stable code of err, defaulting to command_failed.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeCommandFailed
}

// Manager is the whole surface the CLI and API drive. Implementations live
// per platform; name parameters are Interface.Name values.
type Manager interface {
	// Interfaces lists all interfaces with their current configuration.
	Interfaces() ([]Interface, error)
	// SetIP switches an interface to DHCP or a static IPv4 triple.
	SetIP(name string, cfg IPConfig) error
	// SetDNS sets manual resolver servers or returns the interface to
	// automatic DNS.
	SetDNS(name string, cfg DNSConfig) error
	// ScanWifi lists visible wireless networks.
	ScanWifi() ([]WifiNetwork, error)
	// ConnectWifi joins ssid; iface is Interface.Name or "". opts controls
	// the password and how many times to retry a failed association.
	ConnectWifi(iface, ssid string, opts WifiConnectOptions) error
	// DisconnectWifi leaves the currently joined wireless network; iface is
	// Interface.Name or "" for the platform default.
	DisconnectWifi(iface string) error
	// StartWifiAP brings up a Wi-Fi hotspot (AP mode): ssid is the network
	// name, password the WPA2 pre-shared key (empty for an open network);
	// iface is Interface.Name or "" for the platform's Wi-Fi interface.
	StartWifiAP(iface, ssid, password string, opts WifiAPOptions) error
	// StopWifiAP tears down the hotspot previously started by StartWifiAP;
	// opts.ConnName must match the one used to start it.
	StopWifiAP(opts WifiAPOptions) error
	// Proxy reads the current system proxy (iface may narrow the platform's
	// scope, e.g. a macOS network service).
	Proxy(iface string) (ProxyConfig, error)
	// SetProxy writes the system proxy (iface as above).
	SetProxy(iface string, cfg ProxyConfig) error
	// Capabilities reports what this backend can do.
	Capabilities() Capabilities
}

// HostsManager reads and edits the hosts file. All implementations operate
// on a marked section so foreign lines are preserved byte-for-byte.
type HostsManager interface {
	Entries() ([]HostEntry, error)
	Add(ip, hostname string) error
	Remove(hostname string) error
}
