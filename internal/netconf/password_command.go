package netconf

import "strings"

// passwordCommandError maps the usual "run as administrator/root" and
// "user cancelled" failures to stable error codes the UI can explain.
func passwordCommandError(action string, err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "denied") || strings.Contains(msg, "elevation") ||
		strings.Contains(msg, "administrator") || strings.Contains(msg, "privilege") ||
		strings.Contains(msg, "user canceled") || strings.Contains(msg, "user cancelled") {
		return newError(CodePermissionDenied, "%s: %v", action, err)
	}
	return newError(CodeCommandFailed, "%s: %v", action, err)
}
