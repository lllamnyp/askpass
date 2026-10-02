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
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadConfig(t *testing.T) {
	dir := writeConfig(t, "# comment\nserver = 10.99.0.2\n\ntimeout = 30s\nkey = /abs/client.key\n")
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "10.99.0.2:"+DefaultPort || cfg.ServerName != "10.99.0.2" {
		t.Errorf("server %q name %q", cfg.Server, cfg.ServerName)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("timeout %v", cfg.Timeout)
	}
	if cfg.CA != filepath.Join(dir, "ca.crt") || cfg.Key != "/abs/client.key" {
		t.Errorf("paths: ca %q key %q", cfg.CA, cfg.Key)
	}

	cfg, err = LoadConfig(writeConfig(t, "server = laptop.lan:9000\nserver_name = askpass\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "laptop.lan:9000" || cfg.ServerName != "askpass" || cfg.Timeout != DefaultTimeout {
		t.Errorf("got %+v", cfg)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	for name, body := range map[string]string{
		"no server":   "timeout = 5s\n",
		"unknown key": "server = x\nport = 1\n",
		"bad line":    "server x\n",
		"bad timeout": "server = x\ntimeout = soon\n",
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
