// Command askpass is a SUDO_ASKPASS program that fetches the sudo password
// from an askpass-server over mTLS.
//
// Usage:
//
//	SUDO_ASKPASS=/usr/local/bin/askpass sudo -A <command>
//	askpass --csr <name>   generate client.key and client.csr in the config dir
//	askpass --version
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lllamnyp/askpass/internal/client"
	"github.com/lllamnyp/askpass/internal/harden"
	"github.com/lllamnyp/askpass/internal/pki"
)

var version = "dev"

func main() {
	if err := harden.Process(); err != nil {
		fatal("hardening process: %v", err)
	}
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "--version":
			fmt.Println("askpass", version)
			return
		case "--help", "-h":
			fmt.Fprint(os.Stderr, usage)
			return
		case "--csr":
			if len(args) != 2 {
				fatal("usage: askpass --csr <name>")
			}
			if err := makeCSR(args[1]); err != nil {
				fatal("%v", err)
			}
			return
		}
	}
	prompt := ""
	if len(args) > 0 {
		prompt = args[0]
	}
	if err := ask(prompt); err != nil {
		fatal("%v", err)
	}
}

const usage = `askpass: sudo password relay client.

  SUDO_ASKPASS=/path/to/askpass sudo -A <command>
  askpass --csr <name>   create client.key and client.csr in the config directory
  askpass --version

Configuration is read from $ASKPASS_CONFIG_DIR/config, else
$XDG_CONFIG_HOME/askpass/config, else ~/.config/askpass/config.
`

func ask(prompt string) error {
	dir, err := client.DefaultDir()
	if err != nil {
		return err
	}
	cfg, err := client.LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	tlsConfig, err := pki.ClientTLSConfig(cfg.CA, cfg.Cert, cfg.Key, cfg.ServerName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	pw, err := client.Ask(ctx, tlsConfig, cfg.Server, client.Describe(prompt))
	if err != nil {
		if re, ok := errors.AsType[*client.RequestError](err); ok {
			return fmt.Errorf("server refused: %s", re.Reason)
		}
		return err
	}
	// One write of password and newline, from a buffer cleared right after.
	out := make([]byte, len(pw)+1)
	copy(out, pw)
	out[len(pw)] = '\n'
	clear(pw)
	_, err = os.Stdout.Write(out)
	clear(out)
	return err
}

func makeCSR(name string) error {
	dir, err := client.DefaultDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPEM, csrPEM, err := pki.NewClientKeyAndCSR(name)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "client.key")
	csrPath := filepath.Join(dir, "client.csr")
	if err := pki.WriteNew(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := pki.WriteNew(csrPath, csrPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", keyPath, csrPath)
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "askpass: "+format+"\n", args...)
	os.Exit(1)
}
