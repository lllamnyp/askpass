// Package client implements the SUDO_ASKPASS side: it asks the server for a
// password over mTLS.
package client

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/lllamnyp/askpass/internal/protocol"
)

// DefaultTimeout bounds the whole exchange. It is longer than the server's
// default dialog timeout so the server normally reports the timeout itself.
const DefaultTimeout = 90 * time.Second

// ConfigFile is the client configuration file name inside the config dir.
const ConfigFile = "config.yaml"

// Config is the client configuration.
type Config struct {
	// Addr is the server's host:port.
	Addr string
	// ServerName is the name or IP the server certificate must be valid for.
	ServerName string
	CA         string
	Cert       string
	Key        string
	Timeout    time.Duration
}

// fileConfig mirrors config.yaml; unknown keys are an error.
type fileConfig struct {
	Server     string        `mapstructure:"server"`
	Port       int           `mapstructure:"port"`
	ServerName string        `mapstructure:"server_name"`
	CA         string        `mapstructure:"ca"`
	Cert       string        `mapstructure:"cert"`
	Key        string        `mapstructure:"key"`
	Timeout    time.Duration `mapstructure:"timeout"`
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

// LoadConfig reads dir/config.yaml. Each key can be overridden by an
// ASKPASS_<KEY> environment variable, e.g. ASKPASS_SERVER. Relative
// certificate paths resolve against dir.
func LoadConfig(dir string) (*Config, error) {
	path := filepath.Join(dir, ConfigFile)
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("ASKPASS")
	v.SetDefault("port", protocol.DefaultPort)
	v.SetDefault("ca", "ca.crt")
	v.SetDefault("cert", "client.crt")
	v.SetDefault("key", "client.key")
	v.SetDefault("timeout", DefaultTimeout)
	// AutomaticEnv only covers keys viper already knows of.
	v.SetDefault("server", "")
	v.SetDefault("server_name", "")
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var fc fileConfig
	if err := v.UnmarshalExact(&fc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	host := strings.TrimSuffix(strings.TrimPrefix(fc.Server, "["), "]")
	switch {
	case host == "":
		return nil, fmt.Errorf("%s: server is not set", path)
	case strings.Contains(host, ":") && net.ParseIP(host) == nil:
		return nil, fmt.Errorf("%s: server %q must be a host name or IP address; set the port with port", path, fc.Server)
	case fc.Port < 1 || fc.Port > 65535:
		return nil, fmt.Errorf("%s: invalid port %d", path, fc.Port)
	case fc.Timeout <= 0:
		return nil, fmt.Errorf("%s: invalid timeout %v", path, fc.Timeout)
	}
	cfg := &Config{
		Addr:       net.JoinHostPort(host, strconv.Itoa(fc.Port)),
		ServerName: fc.ServerName,
		CA:         fc.CA,
		Cert:       fc.Cert,
		Key:        fc.Key,
		Timeout:    fc.Timeout,
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
