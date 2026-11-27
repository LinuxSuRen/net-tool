package netconf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type auditFakeBackend struct {
	mu        sync.Mutex
	correct   string
	saved     string
	tried     []string
	block     bool
	permanent error
	security  string
}

func (f *auditFakeBackend) SavedWifiPassword(iface, ssid string) (string, error) {
	if f.saved != "" {
		return f.saved, nil
	}
	return "", newError(CodeNotFound, "not saved")
}

func (f *auditFakeBackend) WifiSecurity(iface, ssid string) string { return f.security }

func (f *auditFakeBackend) TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error {
	f.mu.Lock()
	f.tried = append(f.tried, password)
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if f.permanent != nil {
		return f.permanent
	}
	if password == f.correct {
		return nil
	}
	return newError(CodeCommandFailed, "association failed")
}

func (f *auditFakeBackend) attempts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.tried...)
}

func waitAuditJob(t *testing.T, auditor *PasswordAuditor, id string, want string) *PasswordAuditJob {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, ok := auditor.Get(id)
		if !ok {
			t.Fatalf("job %s disappeared", id)
		}
		if job.State == want {
			return job
		}
		if job.State != PasswordAuditRunning {
			t.Fatalf("job state = %s (%s), want %s", job.State, job.Error, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %s", id, want)
	return nil
}

func TestPasswordAuditFindsAndStopsEarly(t *testing.T) {
	backend := &auditFakeBackend{correct: "correctpw1", security: "WPA2"}
	auditor := NewPasswordAuditor(backend)
	job, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, AttemptMS: 50,
		Candidates: []string{"wrongpass1", "correctpw1", "nevertried1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := waitAuditJob(t, auditor, job.ID, PasswordAuditFound)
	if done.Password != "correctpw1" || done.Attempted != 2 {
		t.Errorf("job = %+v, want password correctpw1 after 2 attempts", done)
	}
	if done.Current != "" {
		t.Errorf("current candidate was not cleared: %q", done.Current)
	}
	if got := backend.attempts(); len(got) != 2 {
		t.Errorf("tried %v, want early stop", got)
	}
}

func TestPasswordAuditPrefersSavedPassword(t *testing.T) {
	backend := &auditFakeBackend{saved: "savedpw123", correct: "otherpw123"}
	auditor := NewPasswordAuditor(backend)
	job, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"otherpw123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != PasswordAuditFound || job.Password != "savedpw123" || job.Attempted != 0 {
		t.Errorf("job = %+v, want saved password with no online attempts", job)
	}
	if got := backend.attempts(); len(got) != 0 {
		t.Errorf("online attempts = %v, want none", got)
	}
}

func TestPasswordAuditNotFound(t *testing.T) {
	backend := &auditFakeBackend{}
	auditor := NewPasswordAuditor(backend)
	job, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, AttemptMS: 50,
		Candidates: []string{"wrongpass1", "wrongpass2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := waitAuditJob(t, auditor, job.ID, PasswordAuditNotFound)
	if done.Attempted != 2 || done.Password != "" {
		t.Errorf("job = %+v, want 2 attempts and no password", done)
	}
}

func TestPasswordAuditCancel(t *testing.T) {
	backend := &auditFakeBackend{block: true}
	auditor := NewPasswordAuditor(backend)
	job, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"blockedpwd1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !auditor.Cancel(job.ID) {
		t.Fatal("Cancel returned false")
	}
	waitAuditJob(t, auditor, job.ID, PasswordAuditCanceled)
}

func TestPasswordAuditPermissionErrorStopsImmediately(t *testing.T) {
	backend := &auditFakeBackend{
		permanent: newError(CodePermissionDenied, "run as administrator"),
	}
	auditor := NewPasswordAuditor(backend)
	job, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"pass_one1", "pass_two1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := waitAuditJob(t, auditor, job.ID, PasswordAuditError)
	if done.Attempted != 1 || !strings.Contains(done.Error, "administrator") {
		t.Errorf("job = %+v, want one attempt and permission message", done)
	}
}

func TestPasswordAuditAuthorizationAndSingleJob(t *testing.T) {
	backend := &auditFakeBackend{block: true}
	auditor := NewPasswordAuditor(backend)
	if _, err := auditor.Start(PasswordAuditOptions{SSID: "Home", Candidates: []string{"abcdefgh"}}); err == nil {
		t.Fatal("missing authorization was accepted")
	} else if CodeOf(err) != CodeInvalidArgument {
		t.Errorf("authorization error code = %s", CodeOf(err))
	}
	first, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"abcdefgh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auditor.Cancel(first.ID)
	if _, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"abcdefgh"},
	}); err == nil {
		t.Fatal("a second concurrent audit was accepted")
	}
}

func TestMaskPasswordNeverReturnsPlaintext(t *testing.T) {
	secret := "supersecret"
	masked := maskPassword(secret)
	if strings.Contains(masked, secret) || strings.Contains(masked, "secret") {
		t.Errorf("mask %q leaks password", masked)
	}
	if masked == "" {
		t.Error("empty mask")
	}
}

func TestPasswordAuditNilBackendIsUnsupported(t *testing.T) {
	auditor := NewPasswordAuditor(nil)
	_, err := auditor.Start(PasswordAuditOptions{
		SSID: "Home", Authorized: true, Candidates: []string{"abcdefgh"},
	})
	if err == nil || CodeOf(err) != CodeUnsupported {
		t.Fatalf("nil backend error = %v, want unsupported", err)
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", err), err) {
		t.Error("error wrapping broken")
	}
}
