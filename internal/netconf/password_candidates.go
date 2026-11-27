package netconf

import (
	"strings"
	"unicode"
)

// Common weak passwords that are cheap to try and cover the majority of
// forgotten home-network keys. Kept deliberately short: online attempts are
// serial and every extra candidate costs several seconds.
var builtinWeakPasswords = []string{
	"12345678", "123456789", "1234567890", "11111111", "00000000",
	"88888888", "66666666", "123123", "123456", "654321",
	"qwerty123", "qwertyuiop", "password", "password123", "Password123",
	"iloveyou", "admin123", "abc12345", "a1234567", "1q2w3e4r",
	"qazwsx123", "letmein123", "welcome123", "monkey123", "dragon123",
	"sunshine1", "princess1", "1234qwer", "asdf1234", "zxcvbnm1",
	"5201314aa", "woaini1314", "aa12345678", "net-tool2026",
}

// Short numeric decorations are more likely than a full year sweep.
var candidateSuffixes = []string{
	"1", "12", "123", "1234", "123456", "111", "1111", "888", "8888",
	"2020", "2021", "2022", "2023", "2024", "2025", "2026",
}

// NormalizeCandidateLimit clamps a requested limit to something useful.
func NormalizeCandidateLimit(max int) int {
	if max <= 0 {
		return DefaultCandidateLimit
	}
	if max > MaxCandidateLimit {
		return MaxCandidateLimit
	}
	return max
}

// CleanCandidateWords trims and de-duplicates user supplied words while
// preserving order. Comment lines and obviously invalid PSKs are dropped.
func CleanCandidateWords(words []string, max int) []string {
	if max <= 0 {
		max = MaxWordlistLines
	}
	seen := make(map[string]bool, len(words))
	out := make([]string, 0, len(words))
	for _, raw := range words {
		if len(out) >= max {
			break
		}
		w := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		w = strings.Trim(w, `"'`)
		w = strings.TrimSpace(w)
		if w == "" || strings.HasPrefix(w, "#") || !validCandidate(w) || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

// validCandidate applies the WPA PSK rules (8..63 printable UTF-8 bytes).
func validCandidate(s string) bool {
	n := len(s)
	if n < 8 || n > 63 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\r' || r == '\n' || r == '\t' {
			return false
		}
	}
	return true
}

// ssidSeeds produces a few predictable variants of the network name. Order is
// stable so the same input always produces the same candidate list.
func ssidSeeds(ssid string) []string {
	base := strings.TrimSpace(ssid)
	var seeds []string
	add := func(s string) {
		if s != "" {
			seeds = append(seeds, s)
		}
	}
	add(base)
	add(strings.ToLower(base))
	add(strings.ToUpper(base))
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '-' || r == '_' {
			return -1
		}
		return r
	}, base)
	add(compact)
	add(strings.ToLower(compact))
	runes := []rune(base)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	add(string(runes))
	return seeds
}

func leetCandidate(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'a', 'A':
			b.WriteByte('4')
		case 'e', 'E':
			b.WriteByte('3')
		case 'i', 'I':
			b.WriteByte('1')
		case 'o', 'O':
			b.WriteByte('0')
		case 's', 'S':
			b.WriteByte('5')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func capitalizeCandidate(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// GeneratePasswordCandidates builds a deterministic, de-duplicated list in
// priority order: user words, common passwords, SSID variants, combinations,
// numeric suffixes, leet and case variants. The result is capped at limit.
func GeneratePasswordCandidates(opts CandidateOptions) []string {
	limit := NormalizeCandidateLimit(opts.Max)
	words := CleanCandidateWords(opts.Words, MaxWordlistLines)
	seen := make(map[string]bool, limit)
	out := make([]string, 0, limit)
	add := func(s string) bool {
		if len(out) >= limit {
			return false
		}
		if validCandidate(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		return true
	}

	for _, w := range words {
		if !add(w) {
			return out
		}
	}
	if opts.Builtin {
		for _, w := range builtinWeakPasswords {
			if !add(w) {
				return out
			}
		}
	}

	seeds := ssidSeeds(opts.SSID)
	if opts.Builtin {
		for _, s := range seeds {
			if !add(s) {
				return out
			}
		}
		// A few SSID + weak-password combinations cover names people use as
		// the base of their key (e.g. HomeNet123456).
		weak := builtinWeakPasswords
		if len(weak) > 6 {
			weak = weak[:6]
		}
		shortSeeds := seeds
		if len(shortSeeds) > 3 {
			shortSeeds = shortSeeds[:3]
		}
		for _, w := range weak {
			for _, s := range shortSeeds {
				if !add(s+w) || !add(w+s) {
					return out
				}
			}
		}
	}

	// Suffix/leet/case transformations apply to user words first, then to the
	// strongest builtin seeds and the SSID variants.
	base := append([]string{}, words...)
	if opts.Builtin {
		weak := builtinWeakPasswords
		if len(weak) > 10 {
			weak = weak[:10]
		}
		base = append(base, weak...)
		base = append(base, seeds...)
	}
	for _, s := range base {
		for _, suffix := range candidateSuffixes {
			if !add(s + suffix) {
				return out
			}
		}
	}
	for _, s := range base {
		if !add(leetCandidate(s)) || !add(strings.ToUpper(s)) || !add(capitalizeCandidate(strings.ToLower(s))) {
			return out
		}
	}
	return out
}
