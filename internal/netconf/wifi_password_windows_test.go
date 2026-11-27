//go:build windows

package netconf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const exportedProfileXML = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>M1-68B091</name>
	<SSIDConfig><SSID><name>M1-68B091</name></SSID></SSIDConfig>
	<MSM><security>
		<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>12345678</keyMaterial></sharedKey>
	</security></MSM>
</WLANProfile>`

func TestParseExportedWlanPassword(t *testing.T) {
	profileName, ssidName, password, ok := parseExportedWlanPassword([]byte(exportedProfileXML))
	if !ok || profileName != "M1-68B091" || ssidName != "M1-68B091" || password != "12345678" {
		t.Errorf("parsed = %q, %q, %q, %v", profileName, ssidName, password, ok)
	}
	if _, _, _, ok := parseExportedWlanPassword([]byte("not xml")); ok {
		t.Error("malformed XML was accepted")
	}
}

func TestWindowsSavedWifiPassword(t *testing.T) {
	dir := t.TempDir()
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "export") {
			if err := os.WriteFile(filepath.Join(dir, "M1-68B091.xml"), []byte(exportedProfileXML), 0o600); err != nil {
				return "", err
			}
		}
		return "", nil
	})
	mgr := &windowsManager{query: query, tempDir: func() (string, error) { return dir, nil }}
	password, err := mgr.SavedWifiPassword("", "M1-68B091")
	if err != nil {
		t.Fatalf("SavedWifiPassword: %v", err)
	}
	if password != "12345678" {
		t.Errorf("password = %q, want 12345678", password)
	}
}

func TestWindowsSavedWifiPasswordNotFound(t *testing.T) {
	query := wlanFakeRunner(func(_ string, _ ...string) (string, error) { return "", nil })
	mgr := &windowsManager{query: query, tempDir: func() (string, error) { return t.TempDir(), nil }}
	_, err := mgr.SavedWifiPassword("", "NoSuchNet")
	if CodeOf(err) != CodeNotFound {
		t.Errorf("error = %v, want not_found", err)
	}
}

func TestWindowsTryWifiPasswordUsesTemporaryProfile(t *testing.T) {
	var commands []string
	mutate := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		commands = append(commands, strings.Join(args, " "))
		return "", nil
	})
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "show interfaces") {
			return associatedOut, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query")
	})
	mgr := &windowsManager{
		query: query, mutate: mutate,
		tempDir: func() (string, error) { return t.TempDir(), nil },
	}
	if err := mgr.TryWifiPassword(context.Background(), "", "M1-68B091",
		"12345678", "WPA3-Personal", 100*time.Millisecond); err != nil {
		t.Fatalf("TryWifiPassword: %v", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "wlan add profile filename=") ||
		!strings.Contains(joined, "wlan connect name=net-tool-audit-") ||
		!strings.Contains(joined, "wlan delete profile name=net-tool-audit-") {
		t.Errorf("unexpected commands:\n%s", joined)
	}
	if strings.Contains(joined, "delete profile name=M1-68B091") {
		t.Errorf("original profile was deleted:\n%s", joined)
	}
}

func TestWindowsTryWifiPasswordHonorsCancel(t *testing.T) {
	mutate := wlanFakeRunner(func(_ string, _ ...string) (string, error) { return "", nil })
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "show interfaces") {
			return notAssociatedOut, nil
		}
		return "", nil
	})
	mgr := &windowsManager{
		query: query, mutate: mutate,
		tempDir: func() (string, error) { return t.TempDir(), nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := mgr.TryWifiPassword(ctx, "", "M1-68B091", "12345678", "", time.Second)
	if err == nil {
		t.Fatal("canceled context was ignored")
	}
}
