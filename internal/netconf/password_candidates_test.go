package netconf

import (
	"reflect"
	"testing"
)

func TestGeneratePasswordCandidatesPriorityAndDedupe(t *testing.T) {
	opts := CandidateOptions{
		SSID:    "HomeNet",
		Builtin: true,
		Words:   []string{"mysecretpw", "mysecretpw", "short", "# skipped", "12345678"},
		Max:     200,
	}
	got := GeneratePasswordCandidates(opts)
	if len(got) == 0 || len(got) > 200 {
		t.Fatalf("candidate count = %d, want 1..200", len(got))
	}
	if got[0] != "mysecretpw" {
		t.Errorf("first candidate = %q, want the user supplied word", got[0])
	}
	for _, pwd := range got {
		if !validCandidate(pwd) {
			t.Errorf("invalid PSK in candidates: %q", pwd)
		}
		if pwd == "short" || pwd == "# skipped" {
			t.Errorf("filtered word %q leaked into candidates", pwd)
		}
	}
	seen := map[string]bool{}
	for _, pwd := range got {
		if seen[pwd] {
			t.Fatalf("duplicate candidate %q", pwd)
		}
		seen[pwd] = true
	}
	if !seen["12345678"] {
		t.Error("built-in common password missing")
	}
}

func TestGeneratePasswordCandidatesIsDeterministicAndCapped(t *testing.T) {
	opts := CandidateOptions{SSID: "M1-68B091", Builtin: true, Max: 17}
	a := GeneratePasswordCandidates(opts)
	b := GeneratePasswordCandidates(opts)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("generator is not deterministic:\n%v\n%v", a, b)
	}
	if len(a) != 17 {
		t.Errorf("len = %d, want 17", len(a))
	}
}

func TestGeneratePasswordCandidatesUserListFirst(t *testing.T) {
	got := GeneratePasswordCandidates(CandidateOptions{
		SSID: "HomeNet", Builtin: true, Words: []string{"userword123"}, Max: 50,
	})
	if len(got) < 2 || got[0] != "userword123" || got[1] != "12345678" {
		t.Errorf("unexpected priority order: %v", got[:minInt(3, len(got))])
	}
}

func TestGeneratePasswordCandidatesSkipsInvalidSSIDOnly(t *testing.T) {
	got := GeneratePasswordCandidates(CandidateOptions{Builtin: false, Max: 10})
	if len(got) != 0 {
		t.Errorf("empty options produced %v", got)
	}
}

func TestCleanCandidateWords(t *testing.T) {
	words := []string{" abc12345 ", `"quoted12345"`, "# comment", "abc12345", "tiny", "中文密码888"}
	got := CleanCandidateWords(words, 100)
	want := []string{"abc12345", "quoted12345", "中文密码888"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CleanCandidateWords = %v, want %v", got, want)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
