package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadConfig(t *testing.T) {
	dir := writeConfig(t, "# comment\nserver: 10.99.0.2\ntimeout: 30s\nkey: /abs/client.key\n")
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "10.99.0.2:7676" || cfg.ServerName != "10.99.0.2" {
		t.Errorf("addr %q name %q", cfg.Addr, cfg.ServerName)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("timeout %v", cfg.Timeout)
	}
	if cfg.CA != filepath.Join(dir, "ca.crt") || cfg.Key != "/abs/client.key" {
		t.Errorf("paths: ca %q key %q", cfg.CA, cfg.Key)
	}

	for _, server := range []string{"fd00::2", "\"[fd00::2]\""} {
		cfg, err = LoadConfig(writeConfig(t, "server: "+server+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Addr != "[fd00::2]:7676" || cfg.ServerName != "fd00::2" {
			t.Errorf("ipv6 %s: addr %q name %q", server, cfg.Addr, cfg.ServerName)
		}
	}

	cfg, err = LoadConfig(writeConfig(t, "server: laptop.lan\nport: 9000\nserver_name: askpass\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "laptop.lan:9000" || cfg.ServerName != "askpass" || cfg.Timeout != DefaultTimeout {
		t.Errorf("got %+v", cfg)
	}
}

func TestLoadConfigEnv(t *testing.T) {
	t.Setenv("ASKPASS_SERVER", "10.0.0.1")
	t.Setenv("ASKPASS_PORT", "1234")
	cfg, err := LoadConfig(writeConfig(t, "server: 10.99.0.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "10.0.0.1:1234" {
		t.Errorf("env override ignored: %q", cfg.Addr)
	}
	// No config file at all: the environment alone suffices.
	if _, err := LoadConfig(t.TempDir()); err != nil {
		t.Errorf("env-only config: %v", err)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	for name, body := range map[string]string{
		"no server":      "timeout: 5s\n",
		"unknown key":    "server: x\nlisten: y\n",
		"bad yaml":       "server: [x\n",
		"bad timeout":    "server: x\ntimeout: soon\n",
		"port in server": "server: host:7676\n",
		"bad port":       "server: x\nport: 70000\n",
	} {
		if _, err := LoadConfig(writeConfig(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig(t.TempDir()); err == nil {
		t.Error("missing config accepted")
	}
}

func TestParseStatus(t *testing.T) {
	st, err := parseStatus("Name:\tsudo\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t42\nPPid:\t41\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n")
	if err != nil {
		t.Fatal(err)
	}
	if st.name != "sudo" || st.ppid != 41 || st.euid != 0 {
		t.Errorf("got %+v", st)
	}
	if _, err := parseStatus("Name:\tx\n"); err == nil {
		t.Error("incomplete status accepted")
	}
}

func TestDescribeSelf(t *testing.T) {
	req := Describe("prompt: ")
	if req.Prompt != "prompt: " || req.UID != os.Getuid() || req.Host == "" {
		t.Errorf("got %+v", req)
	}
	// The test binary's parent is the go tool or a shell, never root sudo.
	if len(req.ParentArgs) == 0 || req.ParentName == "" || req.ParentEUID != os.Geteuid() {
		t.Errorf("parent not described: %+v", req)
	}
}
