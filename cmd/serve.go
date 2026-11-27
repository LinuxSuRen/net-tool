package cmd

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/LinuxSuRen/net-tool/internal/api"
	"github.com/LinuxSuRen/net-tool/internal/netconf"
	"github.com/LinuxSuRen/net-tool/web"
)

var (
	serveAddr    string
	serveNoDrift bool
)

// maxPortDrift caps how many consecutive ports are tried when the requested
// one is already in use.
const maxPortDrift = 100

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the Web UI and REST API on localhost",
	Long: `Serve the Web UI and REST API.

Listens on 127.0.0.1:8190 by default. If that port is already in use, the
next free port is tried automatically (up to 100 ports); pass --no-drift to
fail instead. The actual address is always printed. The server never binds a
public interface unless you pass --addr yourself; changing network
configuration is a privileged operation, so keep it local (or tunnel it
securely) and run net-tool with the privileges the operations need.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		api.Version, api.Commit = version, commit
		srv := api.New(netconf.NewManager(), netconf.NewHosts(), web.Dist())
		drift := maxPortDrift
		if serveNoDrift {
			drift = 0
		}
		listener, requestedPort, err := listenWithPortDrift(serveAddr, drift)
		if err != nil {
			return exitErr(cmd, err)
		}
		addr := listener.Addr().String()
		_, actualPort, _ := net.SplitHostPort(addr)
		if requestedPort != "0" && actualPort != requestedPort {
			fmt.Fprintf(cmd.OutOrStdout(), "port %s is in use, drifting to %s\n", requestedPort, actualPort)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "net-tool web UI: http://%s\n", addr)
		if !isLoopbackAddr(addr) {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: bound on a non-loopback address; anyone reachable can change this machine's network settings")
		}
		return http.Serve(listener, srv.Handler())
	},
}

// listenWithPortDrift binds addr, retrying consecutive ports while the
// requested one is occupied. It returns the listener and the originally
// requested port so callers can report a drift.
func listenWithPortDrift(addr string, maxDrift int) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, "", fmt.Errorf("invalid port %q", portStr)
	}

	listener, err := net.Listen("tcp", addr)
	for attempts := 0; err != nil && attempts < maxDrift && port < 65535 && isAddrInUse(err); attempts++ {
		port++
		addr = net.JoinHostPort(host, strconv.Itoa(port))
		listener, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, portStr, err
	}
	return listener, portStr, nil
}

// isLoopbackAddr reports whether host:port points at localhost.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:8190", "listen address")
	serveCmd.Flags().BoolVar(&serveNoDrift, "no-drift", false, "fail instead of trying the next port when the requested one is in use")
	rootCmd.AddCommand(serveCmd)
}
