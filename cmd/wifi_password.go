package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/LinuxSuRen/net-tool/internal/netconf"
)

// readWordlist loads a local password file (UTF-8, one password per line or
// first CSV column). Nothing is uploaded and nothing is written back.
func readWordlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read wordlist %q: %w", path, err)
	}
	if len(data) > netconf.MaxWordlistBytes {
		return nil, fmt.Errorf("wordlist is too large (%d bytes, max %d)", len(data), netconf.MaxWordlistBytes)
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	lines := strings.Split(text, "\n")
	if len(lines) > netconf.MaxWordlistLines {
		lines = lines[:netconf.MaxWordlistLines]
	}
	words := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if comma := strings.IndexByte(line, ','); comma >= 0 {
			line = strings.TrimSpace(line[:comma])
		}
		line = strings.TrimSpace(strings.Trim(line, `"'`))
		if line != "" {
			words = append(words, line)
		}
	}
	return netconf.CleanCandidateWords(words, netconf.MaxWordlistLines), nil
}

func wifiPasswordBackend() (netconf.WifiPasswordBackend, error) {
	backend, ok := newManager(false).(netconf.WifiPasswordBackend)
	if !ok || backend == nil {
		return nil, &netconf.Error{Code: netconf.CodeUnsupported,
			Err: fmt.Errorf("password recovery is not available on this system")}
	}
	return backend, nil
}

var (
	wifiSavedIface string
	wifiSavedDry   bool
)

var wifiSavedPasswordCmd = &cobra.Command{
	Use:   "saved-password <ssid>",
	Short: "Read a Wi-Fi password already saved by the operating system",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend, err := wifiPasswordBackend()
		if err != nil {
			return exitErr(cmd, err)
		}
		_ = wifiSavedDry
		password, err := backend.SavedWifiPassword(wifiSavedIface, args[0])
		if err != nil {
			if netconf.CodeOf(err) == netconf.CodeNotFound {
				if outputJSON {
					printJSON(cmd.OutOrStdout(), map[string]any{"found": false, "password": ""})
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "no saved password for %q\n", args[0])
				return nil
			}
			return exitErr(cmd, err)
		}
		if outputJSON {
			printJSON(cmd.OutOrStdout(), map[string]any{"found": true, "password": password})
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "saved password for %s: %s\n", args[0], password)
		return nil
	},
}

var (
	wifiCandidatesBuiltin  bool
	wifiCandidatesWordlist string
	wifiCandidatesMax      int
)

var wifiCandidatesCmd = &cobra.Command{
	Use:   "candidates <ssid>",
	Short: "Generate likely Wi-Fi passwords without trying any of them",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		words, err := readWordlist(wifiCandidatesWordlist)
		if err != nil {
			return exitErr(cmd, err)
		}
		list := netconf.GeneratePasswordCandidates(netconf.CandidateOptions{
			SSID: args[0], Builtin: wifiCandidatesBuiltin, Words: words, Max: wifiCandidatesMax,
		})
		if outputJSON {
			printJSON(cmd.OutOrStdout(), map[string]any{"total": len(list), "candidates": list})
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%d candidates (showing first 20):\n", len(list))
		for i, pwd := range list {
			if i >= 20 {
				break
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", pwd)
		}
		return nil
	},
}

var (
	wifiRecoverIface      string
	wifiRecoverBuiltin    bool
	wifiRecoverWordlist   string
	wifiRecoverMax        int
	wifiRecoverAttemptMS  int
	wifiRecoverDelayMS    int
	wifiRecoverAuthorized bool
)

var wifiRecoverCmd = &cobra.Command{
	Use:   "recover <ssid>",
	Short: "Try likely passwords one by one until one associates (authorized use only)",
	Long: `Read a password already saved by the OS first. If that fails, this
command tries a small, serial list of common passwords, SSID variants and
optional --wordlist entries. Each attempt creates a temporary profile/connection
and removes it afterwards. Online attempts are slow: 200 candidates can take
many minutes.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !wifiRecoverAuthorized {
			return exitErr(cmd, &netconf.Error{Code: netconf.CodeInvalidArgument,
				Err: fmt.Errorf("pass --i-am-authorized to confirm this is your own network")})
		}
		backend, err := wifiPasswordBackend()
		if err != nil {
			return exitErr(cmd, err)
		}
		words, err := readWordlist(wifiRecoverWordlist)
		if err != nil {
			return exitErr(cmd, err)
		}
		auditor := netconf.NewPasswordAuditor(backend)
		job, err := auditor.Start(netconf.PasswordAuditOptions{
			Interface:  wifiRecoverIface,
			SSID:       args[0],
			Builtin:    wifiRecoverBuiltin,
			Words:      words,
			Max:        wifiRecoverMax,
			AttemptMS:  wifiRecoverAttemptMS,
			DelayMS:    wifiRecoverDelayMS,
			Authorized: true,
		})
		if err != nil {
			return exitErr(cmd, err)
		}
		if job.State == netconf.PasswordAuditFound {
			if outputJSON {
				printJSON(cmd.OutOrStdout(), job)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "saved password for %s: %s\n", args[0], job.Password)
			return nil
		}
		if job.State == netconf.PasswordAuditRunning {
			fmt.Fprintf(cmd.ErrOrStderr(), "trying up to %d candidates (Ctrl+C to stop)\n", job.Total)
		}

		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			current, ok := auditor.Get(job.ID)
			if !ok {
				return exitErr(cmd, fmt.Errorf("password recovery job disappeared"))
			}
			if current.State != netconf.PasswordAuditRunning {
				if outputJSON {
					printJSON(cmd.OutOrStdout(), current)
					return nil
				}
				switch current.State {
				case netconf.PasswordAuditFound:
					fmt.Fprintf(cmd.OutOrStdout(), "password for %s: %s\n", args[0], current.Password)
					return nil
				case netconf.PasswordAuditNotFound:
					return exitErr(cmd, fmt.Errorf("no candidate matched (tried %d); export the list for offline use", current.Attempted))
				case netconf.PasswordAuditCanceled:
					return exitErr(cmd, fmt.Errorf("password recovery canceled after %d attempts", current.Attempted))
				default:
					return exitErr(cmd, fmt.Errorf("password recovery failed: %s", current.Error))
				}
			}
			<-ticker.C
		}
	},
}
