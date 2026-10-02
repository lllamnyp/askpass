// Command askpass is a SUDO_ASKPASS program that fetches the sudo password
// from an askpass-server over mTLS.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/lllamnyp/askpass/internal/client"
	"github.com/lllamnyp/askpass/internal/harden"
	"github.com/lllamnyp/askpass/internal/pki"
)

var version = "dev"

func main() {
	if err := harden.Process(); err != nil {
		fmt.Fprintf(os.Stderr, "askpass: hardening process: %v\n", err)
		os.Exit(1)
	}
	if err := newRootCmd().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "askpass: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "askpass [prompt]",
		Short: "sudo password relay client",
		Long: `askpass fetches the sudo password from askpass-server over mTLS.
sudo runs it with the prompt as its only argument:

  SUDO_ASKPASS=/path/to/askpass sudo -A <command>

Configuration is read from config.yaml in $ASKPASS_CONFIG_DIR, else
$XDG_CONFIG_HOME/askpass, else ~/.config/askpass. Each key can be
overridden by an ASKPASS_<KEY> environment variable.`,
		Args: cobra.MaximumNArgs(1),
		// The prompt is opaque text from sudo -p and may start with "-".
		DisableFlagParsing: true,
		SilenceUsage:       true,
		SilenceErrors:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
				return cmd.Help()
			}
			prompt := ""
			if len(args) == 1 {
				prompt = args[0]
			}
			return ask(cmd.Context(), prompt)
		},
	}
	root.AddCommand(&cobra.Command{
		Use:   "csr <name>",
		Short: "Create client.key and client.csr in the config directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return makeCSR(cmd, args[0])
		},
	}, &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "askpass", version)
		},
	})
	return root
}

func ask(ctx context.Context, prompt string) error {
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
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	pw, err := client.Ask(ctx, tlsConfig, cfg.Addr, client.Describe(prompt))
	if err != nil {
		if re, ok := errors.AsType[*client.RequestError](err); ok {
			return fmt.Errorf("server refused: %s", re.Reason)
		}
		return err
	}
	// Copy, don't append: append may share pw's array, and clear(pw) would
	// wipe out before the write.
	out := make([]byte, len(pw)+1)
	copy(out, pw)
	out[len(pw)] = '\n'
	clear(pw)
	_, err = os.Stdout.Write(out)
	clear(out)
	return err
}

func makeCSR(cmd *cobra.Command, name string) error {
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
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s\n", keyPath, csrPath)
	return nil
}
