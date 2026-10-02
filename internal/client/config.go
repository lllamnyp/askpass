// Package client implements the SUDO_ASKPASS side: it asks the server for a
// password over mTLS.
package client

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultPort is the server's default TCP port.
const DefaultPort = "7676"

// DefaultTimeout bounds the whole exchange. It is longer than the server's
// default dialog timeout so the server normally reports the timeout itself.
const DefaultTimeout = 90 * time.Second

// Config is the client configuration.
type Config struct {
	// Dir is the configuration directory; relative paths resolve against it.
	Dir string
	// Server is the server's host:port.
	Server string
	// ServerName is the name or IP the server certificate must be valid
	// for. Defaults to the host part of Server.
	ServerName string
	CA         string
	Cert       string
	Key        string
	Timeout    time.Duration
}

// DefaultDir returns the configuration directory: $ASKPASS_CONFIG_DIR, else
// $XDG_CONFIG_HOME/askpass, else ~/.config/askpass.
func DefaultDir() (string, error) {
	if d := os.Getenv("ASKPASS_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "askpass"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "askpass"), nil
}

// LoadConfig reads dir/config, a file of "key = value" lines with "#"
// comments. Recognised keys: server, server_name, ca, cert, key, timeout.
func LoadConfig(dir string) (*Config, error) {
	cfg := &Config{
		Dir:     dir,
		CA:      "ca.crt",
		Cert:    "client.crt",
		Key:     "client.key",
		Timeout: DefaultTimeout,
	}
	path := filepath.Join(dir, "config")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "server":
			cfg.Server = v
		case "server_name":
			cfg.ServerName = v
		case "ca":
			cfg.CA = v
		case "cert":
			cfg.Cert = v
		case "key":
			cfg.Key = v
		case "timeout":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("%s:%d: invalid timeout %q", path, n, v)
			}
			cfg.Timeout = d
		default:
			return nil, fmt.Errorf("%s:%d: unknown key %q", path, n, k)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("%s: server is not set", path)
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		// No port given.
		host = cfg.Server
		cfg.Server = net.JoinHostPort(cfg.Server, DefaultPort)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	for _, p := range []*string{&cfg.CA, &cfg.Cert, &cfg.Key} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	return cfg, nil
}
