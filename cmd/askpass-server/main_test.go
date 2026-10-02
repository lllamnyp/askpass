package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// run executes askpass-server with args against a fresh server directory.
func run(t *testing.T, dir string, args ...string) error {
	t.Helper()
	t.Setenv("ASKPASS_SERVER_DIR", dir)
	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	return cmd.Execute()
}

func TestServeRequiresListen(t *testing.T) {
	dir := t.TempDir()
	if err := run(t, dir, "serve"); err == nil || !strings.Contains(err.Error(), "no listen address") {
		t.Errorf("serve without listen: %v", err)
	}
	if err := run(t, dir, "serve", "--listen", "127.0.0.1:7676"); err == nil || !strings.Contains(err.Error(), "includes a port") {
		t.Errorf("listen with a port: %v", err)
	}
}

func TestPortPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := run(t, dir, "init-ca"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte("port: 9000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePort := func(env string, extra ...string) int {
		t.Helper()
		t.Setenv("ASKPASS_SERVER_PORT", env)
		out := filepath.Join(t.TempDir(), "bundle")
		args := append([]string{"issue-client", "--name", "vps", "--server", "10.0.0.1", "--out", out}, extra...)
		if err := run(t, dir, args...); err != nil {
			t.Fatal(err)
		}
		v := viper.New()
		v.SetConfigFile(filepath.Join(out, "config.yaml"))
		if err := v.ReadInConfig(); err != nil {
			t.Fatal(err)
		}
		if v.GetString("server") != "10.0.0.1" {
			t.Errorf("bundle server %q", v.GetString("server"))
		}
		return v.GetInt("port")
	}
	if p := bundlePort(""); p != 9000 {
		t.Errorf("config file: port %d, want 9000", p)
	}
	if p := bundlePort("9001"); p != 9001 {
		t.Errorf("env over config: port %d, want 9001", p)
	}
	if p := bundlePort("9001", "--port", "9002"); p != 9002 {
		t.Errorf("flag over env: port %d, want 9002", p)
	}
}

func TestIssueRequiresNames(t *testing.T) {
	dir := t.TempDir()
	if err := run(t, dir, "init-ca"); err != nil {
		t.Fatal(err)
	}
	if err := run(t, dir, "issue-server"); err == nil {
		t.Error("issue-server without --ip or --dns succeeded")
	}
	if err := run(t, dir, "issue-server", "--ip", "10.0.0.1,10.0.0.2", "--dns", "laptop"); err != nil {
		t.Error(err)
	}
	if err := run(t, dir, "issue-client", "--name", "vps"); err == nil {
		t.Error("issue-client without --server succeeded")
	}
}
