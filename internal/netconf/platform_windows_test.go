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
	if err := mgr.ConnectWifi("", "M1-68B091", "12345678"); err != nil {
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
	err := mgr.ConnectWifi("", "M1-68B091", "12345678")
	if err == nil {
		t.Fatal("netsh exit 0 must not be reported as success when association fails")
	}
	if CodeOf(err) != CodeCommandFailed || !strings.Contains(err.Error(), "M1-68B091") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestConnectWifiDrySkipsVerification(t *testing.T) {
	query := wlanQueryRunner(func(int) string { return notAssociatedOut })
	dry := &DryRunner{}
	mgr := &windowsManager{query: query, mutate: dry}
	if err := mgr.ConnectWifi("", "M1-68B091", "12345678"); err != nil {
		t.Fatalf("dry connect: %v", err)
	}
	if len(dry.Commands) != 3 ||
		!strings.Contains(dry.Commands[0], "wlan delete profile") ||
		!strings.Contains(dry.Commands[1], "wlan add profile") ||
		!strings.Contains(dry.Commands[2], "wlan connect") {
		t.Errorf("dry commands = %v", dry.Commands)
	}
}
