package api

import (
	"errors"
	"net/http"

	"github.com/LinuxSuRen/net-tool/internal/netconf"
)

func (s *Server) passwordBackend(w http.ResponseWriter) netconf.WifiPasswordBackend {
	if s.wifiPwd == nil {
		writeError(w, &netconf.Error{Code: netconf.CodeUnsupported,
			Err: errors.New("password recovery is not available on this system")})
		return nil
	}
	return s.wifiPwd
}

func (s *Server) passwordAuditor(w http.ResponseWriter) *netconf.PasswordAuditor {
	if s.auditor == nil {
		writeError(w, &netconf.Error{Code: netconf.CodeUnsupported,
			Err: errors.New("password recovery is not available on this system")})
		return nil
	}
	return s.auditor
}

// GET /api/wifi/saved-password?ssid=...&interface=...
func (s *Server) handleWifiSavedPassword(w http.ResponseWriter, r *http.Request) {
	backend := s.passwordBackend(w)
	if backend == nil {
		return
	}
	ssid := r.URL.Query().Get("ssid")
	if ssid == "" {
		writeError(w, &netconf.Error{Code: netconf.CodeInvalidArgument, Err: errors.New("ssid is required")})
		return
	}
	password, err := backend.SavedWifiPassword(r.URL.Query().Get("interface"), ssid)
	if err != nil {
		if netconf.CodeOf(err) == netconf.CodeNotFound {
			// A missing saved credential is a normal result, not an error.
			writeData(w, http.StatusOK, map[string]any{"found": false, "password": ""})
			return
		}
		writeError(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]any{"found": true, "password": password})
}

// POST /api/wifi/password-candidates — preview only, never connects.
func (s *Server) handleWifiPasswordCandidates(w http.ResponseWriter, r *http.Request) {
	auditor := s.passwordAuditor(w)
	if auditor == nil {
		return
	}
	var opts netconf.CandidateOptions
	if err := decodeBody(r, &opts); err != nil {
		writeError(w, err)
		return
	}
	candidates := auditor.Candidates(opts)
	writeData(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		"total":      len(candidates),
	})
}

// POST /api/wifi/password-audit — start a background recovery job.
func (s *Server) handleWifiPasswordAuditStart(w http.ResponseWriter, r *http.Request) {
	auditor := s.passwordAuditor(w)
	if auditor == nil {
		return
	}
	var opts netconf.PasswordAuditOptions
	if err := decodeBody(r, &opts); err != nil {
		writeError(w, err)
		return
	}
	job, err := auditor.Start(opts)
	if err != nil {
		writeError(w, err)
		return
	}
	writeData(w, http.StatusOK, job)
}

// GET /api/wifi/password-audit/{id}
func (s *Server) handleWifiPasswordAuditGet(w http.ResponseWriter, r *http.Request) {
	auditor := s.passwordAuditor(w)
	if auditor == nil {
		return
	}
	job, ok := auditor.Get(r.PathValue("id"))
	if !ok {
		writeError(w, &netconf.Error{Code: netconf.CodeNotFound, Err: errors.New("password recovery job not found")})
		return
	}
	writeData(w, http.StatusOK, job)
}

// DELETE /api/wifi/password-audit/{id}
func (s *Server) handleWifiPasswordAuditCancel(w http.ResponseWriter, r *http.Request) {
	auditor := s.passwordAuditor(w)
	if auditor == nil {
		return
	}
	if !auditor.Cancel(r.PathValue("id")) {
		writeError(w, &netconf.Error{Code: netconf.CodeNotFound, Err: errors.New("password recovery job not found or already finished")})
		return
	}
	writeData(w, http.StatusOK, map[string]bool{"ok": true})
}
