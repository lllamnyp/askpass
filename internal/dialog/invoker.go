package dialog

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/lllamnyp/askpass/internal/protocol"
)

// MaxInvoker bounds the total bytes of a request's InvokerArgs. The dialog
// shows "Run from" in full or not at all, so CheckRequest refuses anything
// larger.
const MaxInvoker = 32 << 10

// CheckRequest returns an error, fit to send back to the client, if r cannot
// be shown in full.
func CheckRequest(r *protocol.Request) error {
	n := 0
	for _, a := range r.InvokerArgs {
		n += len(a)
	}
	if n > MaxInvoker {
		return fmt.Errorf("the command that ran sudo is too long to show (%d bytes, limit %d)", n, MaxInvoker)
	}
	return nil
}

// Invoker is the "Run from" command line prepared for display.
type Invoker struct {
	// Summary is one sanitized line for the "Run from" label.
	Summary string
	// Review, if not empty, is the full command line to show in its own
	// scrollable window: a header line, a blank line, then the script as
	// written. It is sanitized but keeps newlines.
	Review string
}

// shells are the programs whose -c script DescribeInvoker shows decoded.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true}

// DescribeInvoker prepares args for display. A shell -c script is shown as
// written, in the review window; so is any other command line too long for
// one label. A short command line is shown on the label alone, shell-quoted.
// Nothing is cut: callers must first refuse requests CheckRequest rejects.
func DescribeInvoker(args []string) Invoker {
	if prefix, script, rest, ok := shellScript(args); ok {
		if w, ok := claudeCode(script); ok && len(rest) == 0 {
			header := "Claude Code Bash tool (sources " + w.source + "; unsets " + strings.Join(w.unsets, ", ")
			if w.stdin != "" {
				header += "; stdin from " + w.stdin
			}
			return Invoker{
				Summary: "Claude Code Bash tool, script in the review window",
				Review:  header + "), script:\n\n" + block(w.body),
			}
		}
		header, _ := formatArgs(prefix, -1)
		header += " followed by the script below"
		if len(rest) > 0 {
			r, _ := formatArgs(rest, -1)
			header += ", with arguments " + r
		}
		name, _ := sanitizeN(path.Base(args[0]), maxField)
		return Invoker{
			Summary: name + " -c script, in the review window",
			Review:  header + ":\n\n" + block(script),
		}
	}
	full, hidden := formatArgs(args, maxField)
	if hidden == 0 {
		return Invoker{Summary: full}
	}
	full, _ = formatArgs(args, -1)
	name, _ := sanitizeN(args[0], 60)
	return Invoker{
		Summary: fmt.Sprintf("%s … (%d characters, in the review window)", name, len([]rune(full))),
		Review:  "Command line:\n\n" + full,
	}
}

func block(script string) string {
	if script == "" {
		return "(empty script)"
	}
	s, _ := escape(script, -1, true)
	return s
}

// shellScript splits a "<shell> [options] -c <script> [args]" command line.
func shellScript(args []string) (prefix []string, script string, rest []string, ok bool) {
	if len(args) < 2 || !shells[strings.TrimPrefix(path.Base(args[0]), "-")] {
		return nil, "", nil, false
	}
	sawC := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--" || a == "-":
			if sawC && i+1 < len(args) {
				return args[:i+1], args[i+1], args[i+2:], true
			}
			return nil, "", nil, false
		case a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+') && isLetters(a[1:]):
			sawC = sawC || a[0] == '-' && strings.Contains(a, "c")
			if strings.ContainsAny(a[1:], "oO") {
				// -o and -O take the next argument as their value.
				i++
			}
		default:
			if !sawC {
				return nil, "", nil, false
			}
			return args[:i], a, args[i+1:], true
		}
	}
	return nil, "", nil, false
}

func isLetters(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// The wrapper Claude Code's Bash tool runs every command in. This is Claude
// Code's own format, not versioned or documented, and has already changed
// once (it gained the unalias block for 'which').
// Anything that doesn't match exactly is shown as a plain shell script.
var (
	claudeHead = regexp.MustCompile(`^source ([A-Za-z0-9_./-]+) 2>/dev/null \|\| true && shopt -u extglob 2>/dev/null \|\| true && `)
	// Go regexps have no backreferences, so claudeCode checks that both
	// names in a block are the same.
	claudeUnset  = regexp.MustCompile(`^\{ \\builtin unalias -- '([A-Za-z_][A-Za-z0-9_]*)'; \\builtin unset -f -- '([A-Za-z_][A-Za-z0-9_]*)'; \} >/dev/null 2>&1 \|\| true && `)
	claudeSuffix = regexp.MustCompile(`^(?: < (/dev/null))? && pwd -P >\| [A-Za-z0-9_./-]+/claude-[0-9a-f]+-cwd$`)
)

// claudeWrapper is what claudeCode found around the command.
type claudeWrapper struct {
	source string   // the snapshot it sources
	unsets []string // the aliases and functions it removes, in order
	stdin  string   // the stdin redirect, if any
	body   string   // the command it evals
}

// claudeCode recognises a Claude Code Bash tool wrapper.
func claudeCode(script string) (w claudeWrapper, ok bool) {
	m := claudeHead.FindStringSubmatch(script)
	if m == nil {
		return w, false
	}
	w.source = m[1]
	s := script[len(m[0]):]
	for {
		u := claudeUnset.FindStringSubmatch(s)
		if u == nil {
			break
		}
		if u[1] != u[2] {
			return w, false
		}
		w.unsets = append(w.unsets, u[1])
		s = s[len(u[0]):]
	}
	s, ok = strings.CutPrefix(s, "eval ")
	if len(w.unsets) == 0 || !ok {
		return w, false
	}
	body, tail, ok := shellWord(s)
	if !ok {
		return w, false
	}
	t := claudeSuffix.FindStringSubmatch(tail)
	if t == nil {
		return w, false
	}
	w.stdin, w.body = t[1], body
	return w, true
}

// shellWord decodes a shell word made only of '…' runs and "'" pieces, the
// form Claude Code quotes the command in, and returns it and what follows.
func shellWord(s string) (word, tail string, ok bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\'' {
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		} else if strings.HasPrefix(s[i:], `"'"`) {
			b.WriteByte('\'')
			i += 3
		} else {
			break
		}
	}
	return b.String(), s[i:], i > 0
}
