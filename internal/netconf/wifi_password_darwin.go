//go:build darwin

package netconf

import (
	"context"
	"strings"
	"time"
)

// SavedWifiPassword reads the AirPort network password from the login
// keychain. macOS may show a Keychain authorization dialog.
func (m *darwinManager) SavedWifiPassword(iface, ssid string) (string, error) {
	_ = iface
	if !validSSID(ssid) {
		return "", newError(CodeInvalidArgument, "invalid SSID %q", ssid)
	}
	out, err := m.query.Run("security", "find-generic-password",
		"-D", "AirPort network password", "-a", ssid, "-w")
	if err != nil {
		// Some macOS versions store the item without the kind attribute.
		out, err = m.query.Run("security", "find-generic-password", "-a", ssid, "-w")
	}
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "could not be found") || strings.Contains(msg, "not found") {
			return "", newError(CodeNotFound, "no saved password for Wi-Fi %q", ssid)
		}
		return "", passwordCommandError("read saved Wi-Fi password from Keychain", err)
	}
	return strings.TrimSpace(out), nil
}

func (m *darwinManager) WifiSecurity(iface, ssid string) string {
	_ = iface
	nets, err := m.ScanWifi()
	if err != nil {
		return ""
	}
	for _, net := range nets {
		if net.SSID == ssid {
			return net.Security
		}
	}
	return ""
}

// TryWifiPassword is intentionally unsupported on macOS: networksetup only
// joins via a saved preferred network, so trying a wrong password would
// overwrite the user's credential. Reading the Keychain is the safe path.
func (m *darwinManager) TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error {
	_ = ctx
	_ = iface
	_ = ssid
	_ = password
	_ = security
	_ = timeout
	return newError(CodeUnsupported,
		"online Wi-Fi password attempts are not supported on macOS; read the saved password from Keychain instead")
}
