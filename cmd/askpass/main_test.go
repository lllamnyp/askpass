package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromptIsNotParsedAsFlags(t *testing.T) {
	t.Setenv("ASKPASS_CONFIG_DIR", t.TempDir())
	for _, prompt := range []string{"--csr", "-p", "[sudo] password for agent: "} {
		cmd := newRootCmd()
		cmd.SetArgs([]string{prompt})
		err := cmd.Execute()
		// Reaching the config load proves the prompt went to ask.
		if err == nil || !strings.Contains(err.Error(), "server is not set") {
			t.Errorf("prompt %q: %v", prompt, err)
		}
	}
}

func TestCSR(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "askpass")
	t.Setenv("ASKPASS_CONFIG_DIR", dir)
	cmd := newRootCmd()
	cmd.SetArgs([]string{"csr", "vps"})
	cmd.SetOut(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "client.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("client.key: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "client.csr")); err != nil {
		t.Error(err)
	}
}
