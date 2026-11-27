package netconf

import (
	"context"
	"time"
)

// Password recovery is deliberately separate from Manager: it is an opt-in
// capability backed by the OS credential store plus short, serial association
// attempts. A backend that can join a network is not automatically a backend
// that may read or guess its password.
type WifiPasswordBackend interface {
	// SavedWifiPassword reads a credential already stored by the OS. Returns
	// not_found when the network is known but has no saved key.
	SavedWifiPassword(iface, ssid string) (string, error)
	// WifiSecurity returns the security advertised by a scan, or "" when the
	// network is hidden. Resolved once per audit, not once per candidate.
	WifiSecurity(iface, ssid string) string
	// TryWifiPassword makes one short association attempt. The backend owns
	// any temporary profile/connection and removes it before returning.
	TryWifiPassword(ctx context.Context, iface, ssid, password, security string, timeout time.Duration) error
}

// Stable job states returned by the password audit API.
const (
	PasswordAuditRunning  = "running"
	PasswordAuditFound    = "found"
	PasswordAuditNotFound = "not_found"
	PasswordAuditCanceled = "canceled"
	PasswordAuditError    = "error"
)

// Defaults keep online guessing small and slow enough to be responsible.
const (
	DefaultCandidateLimit   = 200
	MaxCandidateLimit       = 5000
	DefaultAuditAttemptTime = 4 * time.Second
	MaxAuditAttemptTime     = 30 * time.Second
	DefaultAuditDelay       = 300 * time.Millisecond
	MaxAuditDelay           = 5 * time.Second
	MaxWordlistLines        = 100000
	MaxWordlistBytes        = 1 << 20
)

// CandidateOptions describes what the candidate generator should include.
type CandidateOptions struct {
	SSID    string   `json:"ssid,omitempty"`
	Builtin bool     `json:"builtin,omitempty"`
	Words   []string `json:"words,omitempty"`
	Max     int      `json:"max,omitempty"`
}

// PasswordAuditOptions is one password-recovery job request. Candidates, when
// supplied, replace generation entirely (the UI may send an exported list).
type PasswordAuditOptions struct {
	Interface  string   `json:"interface,omitempty"`
	SSID       string   `json:"ssid"`
	Builtin    bool     `json:"builtin,omitempty"`
	Words      []string `json:"words,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	Max        int      `json:"max,omitempty"`
	AttemptMS  int      `json:"attempt_ms,omitempty"`
	DelayMS    int      `json:"delay_ms,omitempty"`
	Authorized bool     `json:"authorized,omitempty"`
}

// PasswordAuditJob is the public progress snapshot. Password is populated
// only in the found state; Current is always masked.
type PasswordAuditJob struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	Attempted  int        `json:"attempted"`
	Total      int        `json:"total"`
	Current    string     `json:"current,omitempty"`
	Password   string     `json:"password,omitempty"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}
