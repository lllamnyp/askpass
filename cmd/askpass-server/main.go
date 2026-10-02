// Command askpass-server shows a password dialog for each askpass request
// and manages the CA and certificates askpass uses for mTLS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lllamnyp/askpass/internal/dialog"
	"github.com/lllamnyp/askpass/internal/harden"
	"github.com/lllamnyp/askpass/internal/pki"
	"github.com/lllamnyp/askpass/internal/server"
)

var version = "dev"

const (
	defaultListen = "10.99.0.2:7676"
	caName        = "ca"
	serverName    = "server"
)

const usage = `askpass-server: answer askpass sudo password requests from a dialog.

Commands:
  serve          listen for requests and prompt for each one
  init-ca        create the CA
  issue-server   issue the server certificate
  issue-client   issue a client key, certificate and config bundle
  sign-csr       issue a client certificate for a CSR made with "askpass --csr"
  version

Run "askpass-server <command> -h" for the flags of each command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "init-ca":
		err = initCA(args)
	case "issue-server":
		err = issueServer(args)
	case "issue-client":
		err = issueClient(args)
	case "sign-csr":
		err = signCSR(args)
	case "version", "--version":
		fmt.Println("askpass-server", version)
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "askpass-server %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func defaultDir() string {
	if d := os.Getenv("ASKPASS_SERVER_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "askpass-server")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "askpass-server"
	}
	return filepath.Join(home, ".config", "askpass-server")
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir(), "directory holding the CA and server certificate (env ASKPASS_SERVER_DIR)")
	return fs, dir
}

func paths(dir, name string) (cert, key string) {
	return filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
}

func serve(args []string) error {
	fs, dir := newFlags("serve")
	listen := fs.String("listen", defaultListen, "address to listen on")
	timeout := fs.Duration("timeout", server.DefaultTimeout, "how long a request waits for an answer")
	zenity := fs.String("zenity", "zenity", "zenity executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := harden.Process(); err != nil {
		return fmt.Errorf("hardening process: %w", err)
	}
	caCert, _ := paths(*dir, caName)
	cert, key := paths(*dir, serverName)
	tlsConfig, err := pki.ServerTLSConfig(caCert, cert, key)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("listening", "addr", ln.Addr().String(), "timeout", timeout.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &server.Server{
		TLSConfig: tlsConfig,
		Prompter:  &dialog.Zenity{Path: *zenity},
		Timeout:   *timeout,
		Logger:    logger,
	}
	return s.Serve(ctx, ln)
}

func initCA(args []string) error {
	fs, dir := newFlags("init-ca")
	name := fs.String("name", "askpass CA", "CA common name")
	validity := fs.Duration("validity", pki.CAValidity, "CA validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ca, keyPEM, err := pki.NewCA(*name, *validity)
	if err != nil {
		return err
	}
	certPath, keyPath := paths(*dir, caName)
	if err := pki.WriteNew(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := pki.WriteNew(certPath, ca.CertPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", certPath, keyPath)
	return nil
}

func loadCA(dir string) (*pki.CA, error) {
	return pki.LoadCA(paths(dir, caName))
}

func issueServer(args []string) error {
	fs, dir := newFlags("issue-server")
	name := fs.String("name", "askpass-server", "certificate common name")
	ips := fs.String("ip", strings.Split(defaultListen, ":")[0], "comma-separated IP addresses the certificate is valid for")
	dns := fs.String("dns", "", "comma-separated DNS names the certificate is valid for")
	validity := fs.Duration("validity", pki.LeafValidity, "certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ca, err := loadCA(*dir)
	if err != nil {
		return err
	}
	var ipList []net.IP
	for _, s := range splitList(*ips) {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("invalid IP address %q", s)
		}
		ipList = append(ipList, ip)
	}
	certPEM, keyPEM, err := ca.IssueServer(*name, ipList, splitList(*dns), *validity)
	if err != nil {
		return err
	}
	certPath, keyPath := paths(*dir, serverName)
	if err := pki.WriteNew(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := pki.WriteNew(certPath, certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", certPath, keyPath)
	return nil
}

func issueClient(args []string) error {
	fs, dir := newFlags("issue-client")
	name := fs.String("name", "", "client common name, conventionally the client's hostname (required)")
	out := fs.String("out", "", "bundle directory to create (default ./askpass-<name>)")
	srv := fs.String("server", defaultListen, "server address written into the bundle's config")
	validity := fs.Duration("validity", pki.LeafValidity, "certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("-name is required")
	}
	if *out == "" {
		*out = "askpass-" + *name
	}
	ca, err := loadCA(*dir)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.IssueClient(*name, *validity)
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
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
		{"config", []byte("server = " + *srv + "\n"), 0o644},
	}
	for _, f := range files {
		if err := pki.WriteNew(filepath.Join(*out, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	fmt.Printf("wrote client bundle to %s/; copy it to ~/.config/askpass/ on the client\n", *out)
	return nil
}

func signCSR(args []string) error {
	fs, dir := newFlags("sign-csr")
	csrPath := fs.String("csr", "", "CSR file from \"askpass --csr\" (required)")
	out := fs.String("out", "client.crt", "certificate file to write")
	name := fs.String("name", "", "override the common name requested in the CSR")
	validity := fs.Duration("validity", pki.LeafValidity, "certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *csrPath == "" {
		return errors.New("-csr is required")
	}
	csrPEM, err := os.ReadFile(*csrPath)
	if err != nil {
		return err
	}
	ca, err := loadCA(*dir)
	if err != nil {
		return err
	}
	certPEM, err := ca.SignClientCSR(csrPEM, *name, *validity)
	if err != nil {
		return err
	}
	if err := pki.WriteNew(*out, certPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", *out)
	return nil
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
