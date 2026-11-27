//go:build windows

package netconf

import (
	"os"
	"strings"
	"testing"
	"time"
)

// wlanFakeRunner answers commands with a function so tests can change the
// adapter state between the add-profile, connect and verification steps.
type wlanFakeRunner func(name string, args ...string) (string, error)

func (f wlanFakeRunner) Run(name string, args ...string) (string, error) {
	return f(name, args...)
}

const (
	wpa3ScanOut = `SSID 1 : M1-68B091
    网络类型                   : 结构
    身份验证                   : WPA3-Personal
    加密                       : CCMP
`
	notAssociatedOut = `系统上有 1 个接口

    名称                   : WLAN
    状态                   : 已断开连接
`
	associatedOut = `系统上有 1 个接口

    名称                   : WLAN
    SSID                   : M1-68B091
    状态                   : 已连接
`
)

func wlanQueryRunner(interfaces func(int) string) wlanFakeRunner {
	calls := 0
	return func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		switch {
		case strings.Contains(full, "show networks"):
			return wpa3ScanOut, nil
		case strings.Contains(full, "show interfaces"):
			calls++
			return interfaces(calls), nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	}
}

func TestScanWifiRetriesWhenOnlyCurrentNetworkVisible(t *testing.T) {
	scans := 0
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		switch {
		case strings.Contains(full, "show interfaces"):
			return associatedOut, nil
		case strings.Contains(full, "show networks"):
			scans++
			if scans == 1 {
				return wpa3ScanOut, nil // stale: just the connected network
			}
			return wpa3ScanOut + `SSID 2 : OtherNet
    网络类型                   : 结构
    身份验证                   : WPA2-Personal
    加密                       : CCMP
`, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	})
	triggers := 0
	mgr := &windowsManager{
		query:       query,
		scanTries:   3,
		scanTrigger: func() error { triggers++; return nil },
	}
	nets, err := mgr.ScanWifi()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scans != 2 || triggers != 2 {
		t.Errorf("scan calls = %d, scan triggers = %d, want 2 each", scans, triggers)
	}
	if len(nets) != 2 || nets[1].SSID != "OtherNet" {
		t.Errorf("scan result = %+v, want both networks", nets)
	}
}

func TestScanWifiKeepsFullListWithoutRetry(t *testing.T) {
	scans := 0
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		if strings.Contains(full, "show interfaces") {
			return associatedOut, nil
		}
		if strings.Contains(full, "show networks") {
			scans++
			return wpa3ScanOut + `SSID 2 : OtherNet
    身份验证                   : WPA2-Personal
`, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	})
	mgr := &windowsManager{query: query, scanTries: 3}
	if _, err := mgr.ScanWifi(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scans != 1 {
		t.Errorf("scan calls = %d, want 1", scans)
	}
}

func TestConnectWifiVerifiesAssociation(t *testing.T) {
	query := wlanQueryRunner(func(n int) string {
		if n < 3 { // still associating
			return notAssociatedOut
		}
		return associatedOut
	})
	var profile string
	mutate := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		for _, arg := range args {
			if path, ok := strings.CutPrefix(arg, "filename="); ok {
				data, err := os.ReadFile(path)
				if err != nil {
					return "", err
				}
				profile = string(data)
			}
		}
		return "", nil
	})
	mgr := &windowsManager{query: query, mutate: mutate,
		joinTimeout: time.Second, joinPoll: time.Millisecond}
	if err := mgr.ConnectWifi("", "M1-68B091", WifiConnectOptions{Password: "12345678"}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(profile, "<authentication>WPA3SAE</authentication>") ||
		!strings.Contains(profile, "<transitionMode") {
		t.Errorf("WPA3 network got the wrong profile:\n%s", profile)
	}
}

func TestConnectWifiFailsWhenNotAssociated(t *testing.T) {
	mgr := &windowsManager{
		query:       wlanQueryRunner(func(int) string { return notAssociatedOut }),
		mutate:      wlanFakeRunner(func(string, ...string) (string, error) { return "", nil }),
		joinTimeout: 10 * time.Millisecond, joinPoll: time.Millisecond,
	}
	err := mgr.ConnectWifi("", "M1-68B091", WifiConnectOptions{Password: "12345678"})
	if err == nil {
		t.Fatal("netsh exit 0 must not be reported as success when association fails")
	}
	if CodeOf(err) != CodeCommandFailed || !strings.Contains(err.Error(), "M1-68B091") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConnectWifiRetriesAssociation(t *testing.T) {
	associated := false
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		switch {
		case strings.Contains(full, "show networks"):
			return wpa3ScanOut, nil
		case strings.Contains(full, "show interfaces"):
			if associated {
				return associatedOut, nil
			}
			return notAssociatedOut, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	})
	connects := 0
	mutate := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "wlan connect") {
			connects++
			if connects >= 2 {
				associated = true // the second request actually associates
			}
		}
		return "", nil
	})
	mgr := &windowsManager{query: query, mutate: mutate,
		joinTimeout: 20 * time.Millisecond, joinPoll: time.Millisecond}
	err := mgr.ConnectWifi("", "M1-68B091", WifiConnectOptions{Password: "12345678", Attempts: 3})
	if err != nil {
		t.Fatalf("connect with retry: %v", err)
	}
	if connects != 2 {
		t.Errorf("connect attempts = %d, want 2", connects)
	}
}

func TestConnectWifiStopsAtAttemptLimit(t *testing.T) {
	connects := 0
	mutate := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "wlan connect") {
			connects++
		}
		return "", nil
	})
	mgr := &windowsManager{
		query:       wlanQueryRunner(func(int) string { return notAssociatedOut }),
		mutate:      mutate,
		joinTimeout: 10 * time.Millisecond, joinPoll: time.Millisecond,
	}
	err := mgr.ConnectWifi("", "M1-68B091", WifiConnectOptions{Password: "12345678", Attempts: 2})
	if err == nil || !strings.Contains(err.Error(), "after 2 attempts") {
		t.Errorf("expected a bounded retry error, got %v", err)
	}
	if CodeOf(err) != CodeCommandFailed {
		t.Errorf("retry error lost its stable code: %v", err)
	}
	if connects != 2 {
		t.Errorf("connect attempts = %d, want 2", connects)
	}
}

func TestConnectWifiDrySkipsVerification(t *testing.T) {
	query := wlanQueryRunner(func(int) string { return notAssociatedOut })
	dry := &DryRunner{}
	mgr := &windowsManager{query: query, mutate: dry}
	if err := mgr.ConnectWifi("", "M1-68B091", WifiConnectOptions{Password: "12345678"}); err != nil {
		t.Fatalf("dry connect: %v", err)
	}
	if len(dry.Commands) != 3 ||
		!strings.Contains(dry.Commands[0], "wlan delete profile") ||
		!strings.Contains(dry.Commands[1], "wlan add profile") ||
		!strings.Contains(dry.Commands[2], "wlan connect") {
		t.Errorf("dry commands = %v", dry.Commands)
	}
}

func TestDisconnectWifiVerifiesDisassociation(t *testing.T) {
	query := wlanQueryRunner(func(n int) string {
		if n == 1 {
			return associatedOut
		}
		return notAssociatedOut
	})
	var commands []string
	mutate := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		commands = append(commands, strings.Join(args, " "))
		return "", nil
	})
	mgr := &windowsManager{query: query, mutate: mutate,
		joinTimeout: time.Second, joinPoll: time.Millisecond}
	if err := mgr.DisconnectWifi("WLAN"); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "wlan disconnect interface=WLAN") {
		t.Errorf("disconnect commands = %v", commands)
	}
}

func TestDisconnectWifiFailsWhenStillAssociated(t *testing.T) {
	mgr := &windowsManager{
		query:       wlanQueryRunner(func(int) string { return associatedOut }),
		mutate:      wlanFakeRunner(func(string, ...string) (string, error) { return "", nil }),
		joinTimeout: 10 * time.Millisecond, joinPoll: time.Millisecond,
	}
	err := mgr.DisconnectWifi("")
	if err == nil || !strings.Contains(err.Error(), "did not disconnect") {
		t.Errorf("expected an honest disconnect failure, got %v", err)
	}
}

func TestDisconnectWifiDrySkipsVerification(t *testing.T) {
	dry := &DryRunner{}
	mgr := &windowsManager{mutate: dry}
	if err := mgr.DisconnectWifi("WLAN"); err != nil {
		t.Fatalf("dry disconnect: %v", err)
	}
	if len(dry.Commands) != 1 || !strings.Contains(dry.Commands[0], "wlan disconnect") {
		t.Errorf("dry commands = %v", dry.Commands)
	}
}

func TestInterfacesForcesUTF8PowerShellOutput(t *testing.T) {
	var psCommand string
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		if strings.Contains(full, "Get-NetAdapter") {
			psCommand = full
			return `[]`, nil
		}
		if strings.Contains(full, "show interfaces") {
			return notAssociatedOut, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	})
	mgr := &windowsManager{query: query}
	if _, err := mgr.Interfaces(); err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	if !strings.Contains(psCommand, "[Console]::OutputEncoding") ||
		!strings.Contains(psCommand, "UTF8Encoding") {
		t.Errorf("PowerShell command does not force UTF-8 output: %q", psCommand)
	}
}

func TestInterfacesMarksOnlyActiveWiFiAsConnected(t *testing.T) {
	const psOut = `[{"name":"WLAN 3","type":"wifi","up":false},` +
		`{"name":"WLAN","type":"wifi","up":true,"hardware_addr":"AA-BB-CC-DD-EE-FF"}]`
	query := wlanFakeRunner(func(_ string, args ...string) (string, error) {
		full := strings.Join(args, " ")
		switch {
		case strings.Contains(full, "Get-NetAdapter"):
			return psOut, nil
		case strings.Contains(full, "show interfaces"):
			return associatedOut, nil
		}
		return "", newError(CodeCommandFailed, "unexpected query: %s", full)
	})
	ifaces, err := (&windowsManager{query: query}).Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	if ifaces[0].SSID != "" {
		t.Errorf("disabled virtual adapter got current SSID: %q", ifaces[0].SSID)
	}
	if ifaces[1].SSID != "M1-68B091" {
		t.Errorf("active adapter SSID = %q", ifaces[1].SSID)
	}
}
