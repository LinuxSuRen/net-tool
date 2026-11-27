//go:build windows

package netconf

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// exportedWlanProfile mirrors the XML produced by `netsh wlan export profile
// key=clear`. Only local names matter: the root carries a namespace.
type exportedWlanProfile struct {
	XMLName     xml.Name `xml:"WLANProfile"`
	Name        string   `xml:"name"`
	SSIDName    string   `xml:"SSIDConfig>SSID>name"`
	KeyMaterial string   `xml:"MSM>security>sharedKey>keyMaterial"`
}

func parseExportedWlanPassword(data []byte) (profileName, ssidName, password string, ok bool) {
	var p exportedWlanProfile
	if err := xml.Unmarshal(data, &p); err != nil {
		return "", "", "", false
	}
	return p.Name, p.SSIDName, p.KeyMaterial, true
}

func (m *windowsManager) auditTempDir() (string, error) {
	if m.tempDir != nil {
		return m.tempDir()
	}
	return os.MkdirTemp("", "net-tool-wifi-pwd-")
}

// SavedWifiPassword exports the profile with key=clear into a private temp
// directory and reads <keyMaterial>. Exporting XML avoids parsing localized
// `netsh` labels entirely.
func (m *windowsManager) SavedWifiPassword(iface, ssid string) (string, error) {
	_ = iface // WLAN profiles are machine-wide; no interface is needed
	if !validSSID(ssid) {
		return "", newError(CodeInvalidArgument, "invalid SSID %q", ssid)
	}
	dir, err := m.auditTempDir()
	if err != nil {
		return "", newError(CodeCommandFailed, "create temp directory: %v", err)
	}
	defer os.RemoveAll(dir)

	_, err = m.query.Run("netsh", "wlan", "export", "profile",
		"name="+ssid, "key=clear", "folder="+dir)
	if err != nil {
		return "", passwordCommandError("export saved Wi-Fi profile", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", newError(CodeCommandFailed, "read exported profiles: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".xml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		profileName, ssidName, password, ok := parseExportedWlanPassword(data)
		if !ok {
			continue
		}
		if strings.EqualFold(profileName, ssid) || strings.EqualFold(ssidName, ssid) {
			return password, nil
		}
	}
	return "", newError(CodeNotFound, "no saved password for Wi-Fi %q", ssid)
}

func (m *windowsManager) WifiSecurity(iface, ssid string) string {
	_ = iface
	return m.wifiSecurity(ssid)
}

// waitForWlanStateContext is a cancellable, short-lived version of
// waitForWlanState used for one candidate. It polls the real adapter instead
// of trusting netsh's exit code, so a rejected password is reported honestly.
func (m *windowsManager) waitForWlanStateContext(ctx context.Context, iface, want string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = DefaultAuditAttemptTime
	}
	args := []string{"wlan", "show", "interfaces"}
	if iface != "" {
		args = append(args, "name="+iface)
	}
	poll := 200 * time.Millisecond
	if shorter := timeout / 10; shorter > 0 && shorter < poll {
		poll = shorter
	}
	deadline := time.Now().Add(timeout)
	var last string
	for {
		out, err := m.query.Run("netsh", args...)
		if err == nil {
			last = parseWlanCurrentSSID(out)
			if last == want {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
		if !time.Now().Before(deadline) {
			return newError(CodeCommandFailed,
				"Wi-Fi association with %q did not complete (current SSID: %q)", want, last)
		}
	}
}

// TryWifiPassword adds a uniquely named temporary profile for one attempt.
// The user's own profile is never deleted or overwritten; only the temporary
// profile is removed on every path, including cancellation.
func (m *windowsManager) TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validSSID(ssid) {
		return newError(CodeInvalidArgument, "invalid SSID %q", ssid)
	}
	// A rejected password can leave the adapter in "authenticating". Clear it
	// first, otherwise the next connect request is accepted but never
	// associates (the same problem the normal connect retry handles).
	if _, dry := m.mutate.(*DryRunner); !dry {
		_, _ = m.mutate.Run("netsh", "wlan", "disconnect")
		clearTimeout := 2 * time.Second
		if timeout > 0 && timeout < clearTimeout {
			clearTimeout = timeout
		}
		_ = m.waitForWlanStateContext(ctx, iface, "", clearTimeout)
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	profileName := "net-tool-audit-" + randomToken(6)
	profile, err := wlanProfileXMLNamed(profileName, ssid, password, security)
	if err != nil {
		return err
	}
	dir, err := m.auditTempDir()
	if err != nil {
		return newError(CodeCommandFailed, "create temp directory: %v", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, profileName+".xml")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return newError(CodeCommandFailed, "write temp profile: %v", err)
	}

	if _, err := m.mutate.Run("netsh", "wlan", "add", "profile", "filename="+path, "user=all"); err != nil {
		return passwordCommandError("add temporary Wi-Fi profile", err)
	}
	defer func() {
		_, _ = m.mutate.Run("netsh", "wlan", "delete", "profile", "name="+profileName)
	}()

	args := []string{"wlan", "connect", "name=" + profileName}
	if iface != "" {
		args = append(args, "interface="+iface)
	}
	if _, err := m.mutate.Run("netsh", args...); err != nil {
		return passwordCommandError("connect with temporary Wi-Fi profile", err)
	}
	if _, dry := m.mutate.(*DryRunner); dry {
		return nil
	}
	if err := m.waitForWlanStateContext(ctx, iface, ssid, timeout); err != nil {
		return err
	}
	// Deleting the temporary profile below would drop the association. Switch
	// back to the user's own profile first when one exists, so a successful
	// recovery does not leave the machine offline.
	if ctx.Err() == nil {
		if _, err := m.mutate.Run("netsh", "wlan", "connect", "name="+ssid); err == nil {
			_ = m.waitForWlanStateContext(ctx, iface, ssid, timeout)
		}
	}
	return nil
}
