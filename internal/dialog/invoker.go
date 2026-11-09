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
			return w.describe()
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

// The wrapper Claude Code's Bash tool runs every command in:
//
//	<segment> && … && eval '<command>' [< /dev/null] && [<segment> && …] pwd -P >| <dir>/claude-<hex>-cwd
//
// This is Claude Code's own format, not versioned or documented, and it keeps
// changing (it gained an unalias block for 'which', then a bash version
// guard). Segments it is known to use are summarised; any other segment is
// shown as written, so a new one degrades the view instead of losing it.
var (
	claudeSource = regexp.MustCompile(`^source ([A-Za-z0-9_./-]+) 2>/dev/null \|\| true && `)
	// Go regexps have no backreferences, so segment checks that both names
	// in a block are the same; a block where they differ is unrecognised.
	claudeUnset = regexp.MustCompile(`^\{ \\builtin unalias -- '([A-Za-z_][A-Za-z0-9_]*)'; \\builtin unset -f -- '([A-Za-z_][A-Za-z0-9_]*)'; \} >/dev/null 2>&1 \|\| true && `)
	claudeTail  = regexp.MustCompile(`^pwd -P >\| [A-Za-z0-9_./-]+/claude-[0-9a-f]+-cwd$`)
	// claudeFixed are segments with no parameters; they are not shown.
	claudeFixed = []string{
		`{ case "${BASH_VERSINFO-}" in '2'|'3') \builtin printf '%s\n' '__CLAUDE_CODE_DID_NOT_RUN_BASH_TOO_OLD='"${BASH_VERSION-}" >&2; \builtin exit 126; \exit 126;; esac; } && `,
		`shopt -u extglob 2>/dev/null || true && `,
	}
)

// claudeWrapper is what claudeCode found around the command.
type claudeWrapper struct {
	sources []string // the snapshots it sources
	unsets  []string // the aliases and functions it removes
	stdin   string   // the stdin redirect, if any
	body    string   // the command it evals
	// before and after are the unrecognised segments around the eval, as
	// written.
	before, after []string
}

// claudeCode recognises a Claude Code Bash tool wrapper. The eval is the
// first segment that starts with "eval "; segments are split only on a " && "
// that lexSegment finds outside any quoting or grouping.
func claudeCode(script string) (w claudeWrapper, ok bool) {
	s := script
	for !strings.HasPrefix(s, "eval ") {
		if s, ok = w.segment(s, &w.before); !ok {
			return w, false
		}
	}
	w.body, s, ok = shellWord(s[len("eval "):])
	if !ok {
		return w, false
	}
	if t, ok := strings.CutPrefix(s, " < /dev/null"); ok {
		w.stdin, s = "/dev/null", t
	}
	if s, ok = strings.CutPrefix(s, " && "); !ok {
		return w, false
	}
	for !claudeTail.MatchString(s) {
		if s, ok = w.segment(s, &w.after); !ok {
			return w, false
		}
	}
	return w, true
}

// segment consumes one segment and its " && " from the start of s, adding it
// to w or, if it is not one Claude Code is known to use, to unknown.
func (w *claudeWrapper) segment(s string, unknown *[]string) (rest string, ok bool) {
	for _, f := range claudeFixed {
		if t, ok := strings.CutPrefix(s, f); ok {
			return t, true
		}
	}
	if m := claudeSource.FindStringSubmatch(s); m != nil {
		w.sources = append(w.sources, m[1])
		return s[len(m[0]):], true
	}
	if m := claudeUnset.FindStringSubmatch(s); m != nil && m[1] == m[2] {
		w.unsets = append(w.unsets, m[1])
		return s[len(m[0]):], true
	}
	n, ok := lexSegment(s)
	if !ok {
		return "", false
	}
	*unknown = append(*unknown, s[:n])
	return s[n+len(" && "):], true
}

// lexSegment returns the length of the shell text before the first " && "
// in s that is outside quotes, braces and parentheses. It fails on anything
// whose quoting it can't follow exactly as bash would ($'…', $(…), `…`,
// ${…} beyond ${NAME}, here-documents, comments, [[ and ((), since a
// mistake there could make it take quoted text for the outer eval.
func lexSegment(s string) (n int, ok bool) {
	depth := 0
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case strings.HasPrefix(s[i:], " && ") && depth == 0:
			return i, i > 0
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return 0, false
			}
			i += j + 2
		case c == '"':
			j, ok := lexDoubleQuoted(s[i+1:])
			if !ok {
				return 0, false
			}
			i += j + 1
		case c == '\\' && i+1 < len(s):
			i += 2
		case c == '$':
			j, ok := lexDollar(s[i:])
			if !ok {
				return 0, false
			}
			i += j
		case strings.HasPrefix(s[i:], "((") || strings.HasPrefix(s[i:], "[[") || strings.HasPrefix(s[i:], "<<"):
			return 0, false
		case c == '(' || c == '{':
			depth++
			i++
		case c == ')' || c == '}':
			if depth--; depth < 0 {
				return 0, false
			}
			i++
		case c == '`' || c == '#' || c == '\\':
			return 0, false
		default:
			i++
		}
	}
	return 0, false
}

// lexDoubleQuoted returns the length of s up to and including the '"' that
// closes a double-quoted string.
func lexDoubleQuoted(s string) (n int, ok bool) {
	for i := 0; i < len(s); {
		switch s[i] {
		case '"':
			return i + 1, true
		case '\\':
			i += 2
		case '`':
			return 0, false
		case '$':
			j, ok := lexDollar(s[i:])
			if !ok {
				return 0, false
			}
			i += j
		default:
			i++
		}
	}
	return 0, false
}

var plainExpansion = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-)?\}`)

// lexDollar returns the length of the expansion that s starts with.
func lexDollar(s string) (n int, ok bool) {
	if len(s) < 2 {
		return 1, true
	}
	switch s[1] {
	case '(', '\'', '"':
		return 0, false
	case '{':
		m := plainExpansion.FindString(s)
		return len(m), m != ""
	}
	return 1, true
}

func (w claudeWrapper) describe() Invoker {
	var parts []string
	if len(w.sources) > 0 {
		parts = append(parts, "sources "+strings.Join(w.sources, ", "))
	}
	if len(w.unsets) > 0 {
		parts = append(parts, "unsets "+strings.Join(w.unsets, ", "))
	}
	if w.stdin != "" {
		parts = append(parts, "stdin from "+w.stdin)
	}
	header := "Claude Code Bash tool"
	if len(parts) > 0 {
		header += " (" + strings.Join(parts, "; ") + ")"
	}
	if len(w.before)+len(w.after) == 0 {
		return Invoker{
			Summary: "Claude Code Bash tool, script in the review window",
			Review:  header + ", script:\n\n" + block(w.body),
		}
	}
	header += ", with UNRECOGNISED WRAPPER PARTS, which run as written:\n"
	for _, p := range w.before {
		e, _ := escape(p, -1, false)
		header += "  before the script: " + e + "\n"
	}
	for _, p := range w.after {
		e, _ := escape(p, -1, false)
		header += "  after the script: " + e + "\n"
	}
	return Invoker{
		Summary: "Claude Code Bash tool with UNRECOGNISED WRAPPER PARTS, script in the review window",
		Review:  header + "Script:\n\n" + block(w.body),
	}
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
