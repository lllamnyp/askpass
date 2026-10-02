// Command askpass-server shows a password dialog for each askpass request
// and manages the CA and certificates askpass uses for mTLS.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/lllamnyp/askpass/internal/client"
	"github.com/lllamnyp/askpass/internal/dialog"
	"github.com/lllamnyp/askpass/internal/harden"
	"github.com/lllamnyp/askpass/internal/pki"
	"github.com/lllamnyp/askpass/internal/protocol"
	"github.com/lllamnyp/askpass/internal/server"
)

var version = "dev"

const (
	caName     = "ca"
	serverName = "server"
	configFile = "config.yaml"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "askpass-server: %v\n", err)
		os.Exit(1)
	}
}

// app carries the settings shared by every subcommand. A flag can also be
// set by an ASKPASS_SERVER_<FLAG> environment variable or a key in
// <dir>/config.yaml, which take precedence in that order.
type app struct {
	v   *viper.Viper
	dir string
}

func newRootCmd() *cobra.Command {
	a := &app{v: viper.New()}
	a.v.SetEnvPrefix("ASKPASS_SERVER")
	a.v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	a.v.AutomaticEnv()

	root := &cobra.Command{
		Use:               "askpass-server",
		Short:             "Answer askpass sudo password requests from a dialog",
		Version:           version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: a.load,
	}
	root.PersistentFlags().String("dir", "", "directory holding the CA, server certificate and config.yaml (default $XDG_CONFIG_HOME/askpass-server or ~/.config/askpass-server)")
	root.AddCommand(a.serveCmd(), a.initCACmd(), a.issueServerCmd(), a.issueClientCmd(), a.signCSRCmd())
	return root
}

// load binds the running command's flags, resolves the directory and reads
// its config.yaml if there is one.
func (a *app) load(cmd *cobra.Command, _ []string) error {
	if err := a.v.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	a.dir = a.v.GetString("dir")
	if a.dir == "" {
		if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
			a.dir = filepath.Join(d, "askpass-server")
		} else if home, err := os.UserHomeDir(); err == nil {
			a.dir = filepath.Join(home, ".config", "askpass-server")
		} else {
			return errors.New("cannot determine the home directory; pass --dir or set ASKPASS_SERVER_DIR")
		}
	}
	a.v.SetConfigFile(filepath.Join(a.dir, configFile))
	if err := a.v.ReadInConfig(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading %s: %w", a.v.ConfigFileUsed(), err)
	}
	return nil
}

func (a *app) paths(name string) (cert, key string) {
	return filepath.Join(a.dir, name+".crt"), filepath.Join(a.dir, name+".key")
}

func (a *app) loadCA() (*pki.CA, error) {
	return pki.LoadCA(a.paths(caName))
}

func (a *app) serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Listen for requests and prompt for each one",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			listen := a.v.GetString("listen")
			if listen == "" {
				return errors.New("no listen address: pass --listen, set ASKPASS_SERVER_LISTEN, or set listen in " + filepath.Join(a.dir, configFile))
			}
			return a.serve(cmd.Context(), listen, a.v.GetInt("port"))
		},
	}
	f := cmd.Flags()
	f.String("listen", "", "IP address or host name to listen on (required)")
	f.Int("port", protocol.DefaultPort, "TCP port to listen on")
	f.Duration("timeout", server.DefaultTimeout, "how long a request waits for an answer")
	f.String("zenity", "zenity", "zenity executable")
	return cmd
}

func (a *app) serve(ctx context.Context, listen string, port int) error {
	if _, _, err := net.SplitHostPort(listen); err == nil {
		return fmt.Errorf("listen address %q includes a port; set it with --port", listen)
	}
	if err := harden.Process(); err != nil {
		return fmt.Errorf("hardening process: %w", err)
	}
	caCert, _ := a.paths(caName)
	cert, key := a.paths(serverName)
	tlsConfig, err := pki.ServerTLSConfig(caCert, cert, key)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(strings.Trim(listen, "[]"), strconv.Itoa(port)))
	if err != nil {
		return err
	}
	timeout := a.v.GetDuration("timeout")
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("listening", "addr", ln.Addr().String(), "timeout", timeout.String())

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &server.Server{
		TLSConfig: tlsConfig,
		Prompter:  &dialog.Zenity{Path: a.v.GetString("zenity")},
		Timeout:   timeout,
		Logger:    logger,
	}
	return s.Serve(ctx, ln)
}

func (a *app) initCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-ca",
		Short: "Create the CA",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(a.dir, 0o700); err != nil {
				return err
			}
			ca, keyPEM, err := pki.NewCA(a.v.GetString("name"), a.v.GetDuration("validity"))
			if err != nil {
				return err
			}
			certPath, keyPath := a.paths(caName)
			if err := pki.WriteNew(keyPath, keyPEM, 0o600); err != nil {
				return err
			}
			if err := pki.WriteNew(certPath, ca.CertPEM, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s\n", certPath, keyPath)
			return nil
		},
	}
	cmd.Flags().String("name", "askpass CA", "CA common name")
	cmd.Flags().Duration("validity", pki.CAValidity, "CA validity")
	return cmd
}

func (a *app) issueServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue-server",
		Short: "Issue the server certificate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ips []net.IP
			for _, s := range a.v.GetStringSlice("ip") {
				ip := net.ParseIP(s)
				if ip == nil {
					return fmt.Errorf("invalid IP address %q", s)
				}
				ips = append(ips, ip)
			}
			ca, err := a.loadCA()
			if err != nil {
				return err
			}
			certPEM, keyPEM, err := ca.IssueServer(a.v.GetString("name"), ips, a.v.GetStringSlice("dns"), a.v.GetDuration("validity"))
			if err != nil {
				return err
			}
			certPath, keyPath := a.paths(serverName)
			if err := pki.WriteNew(keyPath, keyPEM, 0o600); err != nil {
				return err
			}
			if err := pki.WriteNew(certPath, certPEM, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s\n", certPath, keyPath)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSlice("ip", nil, "IP addresses the certificate is valid for")
	f.StringSlice("dns", nil, "DNS names the certificate is valid for")
	f.String("name", "askpass-server", "certificate common name")
	f.Duration("validity", pki.LeafValidity, "certificate validity")
	cmd.MarkFlagsOneRequired("ip", "dns")
	return cmd
}

func (a *app) issueClientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue-client",
		Short: "Issue a client key, certificate and config bundle",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			name, out := a.v.GetString("name"), a.v.GetString("out")
			if out == "" {
				out = "askpass-" + name
			}
			ca, err := a.loadCA()
			if err != nil {
				return err
			}
			certPEM, keyPEM, err := ca.IssueClient(name, a.v.GetDuration("validity"))
			if err != nil {
				return err
			}
			if err := os.Mkdir(out, 0o700); err != nil {
				return err
			}
			files := []struct {
				name string
				data []byte
				mode os.FileMode
			}{
				{"client.key", keyPEM, 0o600},
				{"client.crt", certPEM, 0o644},
				{"ca.crt", ca.CertPEM, 0o644},
			}
			for _, f := range files {
				if err := pki.WriteNew(filepath.Join(out, f.name), f.data, f.mode); err != nil {
					return err
				}
			}
			cfg := viper.New()
			cfg.Set("server", a.v.GetString("server"))
			cfg.Set("port", a.v.GetInt("port"))
			if err := cfg.SafeWriteConfigAs(filepath.Join(out, client.ConfigFile)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote client bundle to %s/; copy it to ~/.config/askpass/ on the client\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.String("name", "", "client common name, conventionally the client's hostname")
	f.String("server", "", "server IP address or host name written into the bundle's config")
	f.Int("port", protocol.DefaultPort, "server port written into the bundle's config")
	f.String("out", "", "bundle directory to create (default ./askpass-<name>)")
	f.Duration("validity", pki.LeafValidity, "certificate validity")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("server")
	return cmd
}

func (a *app) signCSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign-csr",
		Short: `Issue a client certificate for a CSR made with "askpass csr"`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			csrPEM, err := os.ReadFile(a.v.GetString("csr"))
			if err != nil {
				return err
			}
			ca, err := a.loadCA()
			if err != nil {
				return err
			}
			certPEM, err := ca.SignClientCSR(csrPEM, a.v.GetString("name"), a.v.GetDuration("validity"))
			if err != nil {
				return err
			}
			out := a.v.GetString("out")
			if err := pki.WriteNew(out, certPEM, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.String("csr", "", `CSR file from "askpass csr"`)
	f.String("out", "client.crt", "certificate file to write")
	f.String("name", "", "override the common name requested in the CSR")
	f.Duration("validity", pki.LeafValidity, "certificate validity")
	_ = cmd.MarkFlagRequired("csr")
	return cmd
}
