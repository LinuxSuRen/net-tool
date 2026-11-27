package netconf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// randomToken gives temporary profiles/connections a name that cannot clash
// with anything the user saved.
func randomToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// PasswordAuditor runs at most one password-recovery job at a time. It is
// platform independent: the backend supplies saved-credential reads and short
// association attempts, while this type owns ordering, progress and cancel.
type PasswordAuditor struct {
	mu      sync.Mutex
	backend WifiPasswordBackend
	jobs    map[string]*PasswordAuditJob
	cancels map[string]context.CancelFunc
	seq     uint64
}

// NewPasswordAuditor wires an auditor to a platform backend. A nil backend is
// allowed (the API then reports unsupported).
func NewPasswordAuditor(backend WifiPasswordBackend) *PasswordAuditor {
	return &PasswordAuditor{
		backend: backend,
		jobs:    map[string]*PasswordAuditJob{},
		cancels: map[string]context.CancelFunc{},
	}
}

// NormalizeAuditAttemptTime clamps the per-candidate association timeout.
func NormalizeAuditAttemptTime(ms int) time.Duration {
	if ms <= 0 {
		return DefaultAuditAttemptTime
	}
	d := time.Duration(ms) * time.Millisecond
	if d > MaxAuditAttemptTime {
		return MaxAuditAttemptTime
	}
	return d
}

// NormalizeAuditDelay clamps the pause between two attempts.
func NormalizeAuditDelay(ms int) time.Duration {
	if ms < 0 {
		ms = 0
	}
	d := time.Duration(ms) * time.Millisecond
	if d > MaxAuditDelay {
		return MaxAuditDelay
	}
	return d
}

func maskPassword(password string) string {
	n := len([]rune(password))
	if n == 0 {
		return ""
	}
	if n > 10 {
		n = 10
	}
	if n < 3 {
		n = 3
	}
	return strings.Repeat("•", n)
}

func (a *PasswordAuditor) update(id string, change func(*PasswordAuditJob)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if j := a.jobs[id]; j != nil {
		change(j)
	}
}

func copyJob(j *PasswordAuditJob) *PasswordAuditJob {
	if j == nil {
		return nil
	}
	c := *j
	return &c
}

// Candidates returns the list a job with these options would try.
func (a *PasswordAuditor) Candidates(opts CandidateOptions) []string {
	return GeneratePasswordCandidates(opts)
}

// Start validates, queues and launches a recovery job. The returned snapshot
// is safe to serialize while the job keeps running in the background.
func (a *PasswordAuditor) Start(opts PasswordAuditOptions) (*PasswordAuditJob, error) {
	if a == nil || a.backend == nil {
		return nil, newError(CodeUnsupported, "password recovery is not available on this system")
	}
	if !opts.Authorized {
		return nil, newError(CodeInvalidArgument, "explicit authorization is required")
	}
	if !validSSID(opts.SSID) {
		return nil, newError(CodeInvalidArgument, "invalid SSID %q", opts.SSID)
	}

	// The best answer is the credential the OS already has. Do this before
	// generating or trying anything else; a failed read (usually not_found)
	// simply falls through to the small candidate list.
	if saved, err := a.backend.SavedWifiPassword(opts.Interface, opts.SSID); err == nil && saved != "" {
		a.mu.Lock()
		a.seq++
		now := time.Now()
		job := &PasswordAuditJob{
			ID:         fmt.Sprintf("audit-%d-%d", now.UnixNano(), a.seq),
			State:      PasswordAuditFound,
			Password:   saved,
			StartedAt:  now,
			FinishedAt: &now,
		}
		a.jobs[job.ID] = job
		snapshot := copyJob(job)
		a.mu.Unlock()
		return snapshot, nil
	}

	var candidates []string
	if len(opts.Candidates) > 0 {
		candidates = CleanCandidateWords(opts.Candidates, MaxCandidateLimit)
	} else {
		candidates = GeneratePasswordCandidates(CandidateOptions{
			SSID: opts.SSID, Builtin: opts.Builtin, Words: opts.Words, Max: opts.Max,
		})
	}
	if len(candidates) == 0 {
		return nil, newError(CodeInvalidArgument, "no usable candidate passwords (check length 8..63)")
	}

	timeout := NormalizeAuditAttemptTime(opts.AttemptMS)
	delay := NormalizeAuditDelay(opts.DelayMS)
	security := a.backend.WifiSecurity(opts.Interface, opts.SSID)

	a.mu.Lock()
	for _, j := range a.jobs {
		if j.State == PasswordAuditRunning {
			a.mu.Unlock()
			return nil, newError(CodeCommandFailed, "another password recovery is already running")
		}
	}
	a.seq++
	id := fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), a.seq)
	job := &PasswordAuditJob{
		ID: id, State: PasswordAuditRunning, Total: len(candidates), StartedAt: time.Now(),
	}
	a.jobs[id] = job
	ctx, cancel := context.WithCancel(context.Background())
	a.cancels[id] = cancel
	snapshot := copyJob(job)
	a.mu.Unlock()

	go a.run(id, ctx, opts.Interface, opts.SSID, security, candidates, timeout, delay)
	return snapshot, nil
}

// Get returns the current public snapshot of a job.
func (a *PasswordAuditor) Get(id string) (*PasswordAuditJob, bool) {
	if a == nil {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	j, ok := a.jobs[id]
	return copyJob(j), ok
}

// Cancel asks a running job to stop. The job state becomes canceled even if
// the backend is still finishing its current association attempt.
func (a *PasswordAuditor) Cancel(id string) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	j := a.jobs[id]
	if j == nil || j.State != PasswordAuditRunning {
		a.mu.Unlock()
		return false
	}
	now := time.Now()
	j.State = PasswordAuditCanceled
	j.Current = ""
	j.FinishedAt = &now
	cancel := a.cancels[id]
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

func (a *PasswordAuditor) finish(id, state, current, password, message string) {
	a.update(id, func(j *PasswordAuditJob) {
		if j.State != PasswordAuditRunning {
			return
		}
		now := time.Now()
		j.State = state
		j.Current = current
		j.Password = password
		j.Error = message
		j.FinishedAt = &now
	})
}

func (a *PasswordAuditor) run(id string, ctx context.Context, iface, ssid, security string,
	candidates []string, timeout, delay time.Duration) {

	defer func() {
		a.mu.Lock()
		delete(a.cancels, id)
		a.mu.Unlock()
	}()

	for i, password := range candidates {
		select {
		case <-ctx.Done():
			a.finish(id, PasswordAuditCanceled, "", "", "")
			return
		default:
		}

		a.update(id, func(j *PasswordAuditJob) {
			j.Attempted = i + 1
			j.Current = maskPassword(password)
		})
		err := a.backend.TryWifiPassword(ctx, iface, ssid, password, security, timeout)
		if err == nil {
			a.finish(id, PasswordAuditFound, "", password, "")
			return
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			a.finish(id, PasswordAuditCanceled, "", "", "")
			return
		}
		// Permission and configuration errors cannot be fixed by trying more
		// passwords, so stop early with a useful reason.
		switch CodeOf(err) {
		case CodePermissionDenied, CodeUnsupported, CodeInvalidArgument:
			a.finish(id, PasswordAuditError, "", "", err.Error())
			return
		}
		if i < len(candidates)-1 && delay > 0 {
			select {
			case <-ctx.Done():
				a.finish(id, PasswordAuditCanceled, "", "", "")
				return
			case <-time.After(delay):
			}
		}
	}
	a.finish(id, PasswordAuditNotFound, "", "", "")
}
