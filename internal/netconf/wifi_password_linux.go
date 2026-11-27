//go:build linux

package netconf

import (
	"context"
	"strconv"
	"strings"
	"time"
)

func (m *linuxManager) SavedWifiPassword(iface, ssid string) (string, error) {
	_ = iface // NetworkManager connections are machine-wide
	if !m.hasNM {
		return "", newError(CodeUnsupported, "NetworkManager (nmcli) not found; reading saved Wi-Fi passwords is unavailable")
	}
	if !validSSID(ssid) {
		return "", newError(CodeInvalidArgument, "invalid SSID %q", ssid)
	}

	names := []string{ssid}
	out, err := m.query.Run("nmcli", "-t", "-e", "no", "-f", "NAME,TYPE", "connection", "show")
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) == 2 && strings.EqualFold(parts[1], "802-11-wireless") && parts[0] != "" {
				names = append(names, parts[0])
			}
		}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ssidOut, err := m.query.Run("nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", name)
		if err != nil || strings.TrimSpace(ssidOut) != ssid {
			continue
		}
		psk, err := m.query.Run("nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", name)
		if err != nil {
			return "", passwordCommandError("read saved Wi-Fi password", err)
		}
		return strings.TrimSpace(psk), nil
	}
	return "", newError(CodeNotFound, "no saved password for Wi-Fi %q", ssid)
}

func (m *linuxManager) WifiSecurity(iface, ssid string) string {
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

// TryWifiPassword uses a temporary NetworkManager connection name so the
// user's existing profile is left untouched. nmcli deletes the connection on
// every path, including a rejected password.
func (m *linuxManager) TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error {
	_ = security // nmcli reads the network's security itself
	if err := ctx.Err(); err != nil {
		return err
	}
	if !m.hasNM {
		return newError(CodeUnsupported, "NetworkManager (nmcli) not found; password attempts are unavailable")
	}
	if !validSSID(ssid) {
		return newError(CodeInvalidArgument, "invalid SSID %q", ssid)
	}
	profile := "net-tool-audit-" + randomToken(6)

	args := []string{}
	if timeout > 0 {
		secs := int((timeout + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		args = append(args, "--wait", strconv.Itoa(secs))
	}
	args = append(args, "device", "wifi", "connect", ssid, "password", password, "name", profile)
	if iface != "" {
		args = append(args, "ifname", iface)
	}
	defer func() {
		_, _ = m.mutate.Run("nmcli", "connection", "delete", profile)
	}()
	if _, err := m.mutate.Run("nmcli", args...); err != nil {
		return passwordCommandError("connect with temporary Wi-Fi connection", err)
	}
	if _, dry := m.mutate.(*DryRunner); dry {
		return nil
	}

	verify := []string{"-t", "-f", "GENERAL.CONNECTION", "device", "show"}
	if iface != "" {
		verify = append(verify, iface)
	}
	deadline := time.Now().Add(timeout)
	for {
		out, err := m.query.Run("nmcli", verify...)
		if err == nil {
			for _, line := range strings.Split(out, "\n") {
				if strings.TrimSpace(line) == profile {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if !time.Now().Before(deadline) {
			return newError(CodeCommandFailed,
				"Wi-Fi association with %q did not complete (temporary connection: %q)", ssid, profile)
		}
	}
}
