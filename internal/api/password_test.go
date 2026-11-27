package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LinuxSuRen/net-tool/internal/netconf"
)

// fakePasswordManager adds the optional password backend to the shared API
// fake, so endpoint tests do not need a real OS credential store.
type fakePasswordManager struct {
	*fakeManager
	saved string
	tried []string
}

func (f *fakePasswordManager) SavedWifiPassword(iface, ssid string) (string, error) {
	if f.saved == "" {
		return "", &netconf.Error{Code: netconf.CodeNotFound, Err: errStr("not saved")}
	}
	return f.saved, nil
}

func (f *fakePasswordManager) WifiSecurity(iface, ssid string) string { return "WPA2-Personal" }

func (f *fakePasswordManager) TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error {
	f.tried = append(f.tried, password)
	if password == "12345678" {
		return nil
	}
	return &netconf.Error{Code: netconf.CodeCommandFailed, Err: errStr("association failed")}
}

func newPasswordTestServer(t *testing.T, saved string) (*Server, *fakePasswordManager) {
	t.Helper()
	mgr := &fakePasswordManager{
		fakeManager: &fakeManager{ifaces: []netconf.Interface{{Name: "WLAN", Type: "wifi"}}},
		saved:       saved,
	}
	srv := New(mgr, netconf.NewHostsAt(filepath.Join(t.TempDir(), "hosts")), nil)
	return srv, mgr
}

func TestSavedPasswordEndpoint(t *testing.T) {
	srv, _ := newPasswordTestServer(t, "12345678")
	rec, payload := doJSON(t, srv, http.MethodGet,
		"/api/wifi/saved-password?ssid=Home&interface=WLAN", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	data := payload["data"].(map[string]any)
	if data["password"] != "12345678" || data["found"] != true {
		t.Errorf("data = %v", data)
	}

	srv, _ = newPasswordTestServer(t, "")
	_, payload = doJSON(t, srv, http.MethodGet, "/api/wifi/saved-password?ssid=Home", "")
	data = payload["data"].(map[string]any)
	if data["found"] != false {
		t.Errorf("missing password should report found=false, got %v", data)
	}
}

func TestCandidateEndpoint(t *testing.T) {
	srv, _ := newPasswordTestServer(t, "")
	rec, payload := doJSON(t, srv, http.MethodPost, "/api/wifi/password-candidates",
		`{"ssid":"HomeNet","builtin":true,"max":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	data := payload["data"].(map[string]any)
	if data["total"].(float64) != 5 || len(data["candidates"].([]any)) != 5 {
		t.Errorf("data = %v", data)
	}
}

func TestPasswordAuditEndpoint(t *testing.T) {
	srv, mgr := newPasswordTestServer(t, "")
	body := `{"ssid":"Home","authorized":true,"attempt_ms":50,"delay_ms":0,
		"candidates":["wrongpass1","12345678"]}`
	rec, payload := doJSON(t, srv, http.MethodPost, "/api/wifi/password-audit", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	job := payload["data"].(map[string]any)
	id := job["id"].(string)
	if job["state"] != netconf.PasswordAuditRunning {
		t.Fatalf("job = %v", job)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		_, payload = doJSON(t, srv, http.MethodGet, "/api/wifi/password-audit/"+id, "")
		job = payload["data"].(map[string]any)
		if job["state"] != netconf.PasswordAuditRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit job never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if job["state"] != netconf.PasswordAuditFound || job["password"] != "12345678" {
		t.Errorf("job = %v", job)
	}
	current, _ := job["current"].(string)
	if strings.Contains(current, "12345678") {
		t.Errorf("progress leaked the password: %v", job["current"])
	}
	if len(mgr.tried) != 2 {
		t.Errorf("tried %v", mgr.tried)
	}
}

func TestPasswordAuditEndpointUsesSavedPasswordFirst(t *testing.T) {
	srv, mgr := newPasswordTestServer(t, "savedpw123")
	rec, payload := doJSON(t, srv, http.MethodPost, "/api/wifi/password-audit",
		`{"ssid":"Home","authorized":true,"candidates":["wrongpass1"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	job := payload["data"].(map[string]any)
	if job["state"] != netconf.PasswordAuditFound || job["password"] != "savedpw123" {
		t.Errorf("job = %v, want the saved password", job)
	}
	if job["attempted"].(float64) != 0 || len(mgr.tried) != 0 {
		t.Errorf("attempted = %v, tried = %v, want no online attempts", job["attempted"], mgr.tried)
	}
}

func TestPasswordAuditEndpointRequiresAuthorization(t *testing.T) {
	srv, _ := newPasswordTestServer(t, "")
	rec, payload := doJSON(t, srv, http.MethodPost, "/api/wifi/password-audit",
		`{"ssid":"Home","candidates":["abcdefgh"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	problem := payload["error"].(map[string]any)
	if problem["code"] != netconf.CodeInvalidArgument {
		t.Errorf("error = %v", problem)
	}
}
