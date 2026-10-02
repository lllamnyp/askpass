// Package dialog asks the human at the server for a password.
package dialog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lllamnyp/askpass/internal/protocol"
)

// ErrDenied is returned when the user declines the request.
var ErrDenied = errors.New("denied by user")

// Prompt is everything the dialog shows about one request.
type Prompt struct {
	// ClientName is the common name of the verified client certificate.
	ClientName string
	// RemoteAddr is the client's network address.
	RemoteAddr string
	// Request holds the details the client asserted about itself.
	Request *protocol.Request
	// Deadline is when the request expires unanswered.
	Deadline time.Time
}

// Prompter shows a prompt and returns the password typed in. The returned
// slice belongs to the caller, who must clear it. Ask returns ErrDenied if
// the user declines, and ctx.Err() if ctx ends first.
type Prompter interface {
	Ask(ctx context.Context, p *Prompt) ([]byte, error)
}

// maxField bounds every client-supplied string shown in the dialog.
const maxField = 300

// Lines renders the prompt as label/value pairs of sanitized plain text. Every
// value is single-line, with control and formatting characters escaped, so a
// client cannot forge extra lines or hide text.
func (p *Prompt) Lines() [][2]string {
	r := p.Request
	lines := [][2]string{
		{"Host", fmt.Sprintf("%s (certificate %q from %s)", sanitize(r.Host), sanitize(p.ClientName), p.RemoteAddr)},
		{"User", fmt.Sprintf("%s (uid %d)", sanitize(r.User), r.UID)},
		{"Command", FormatArgs(r.ParentArgs)},
		{"Run from", FormatArgs(r.InvokerArgs)},
		{"Directory", sanitize(r.Cwd)},
		{"Prompt", sanitize(r.Prompt)},
	}
	if !IsSudo(r) {
		lines = append(lines, [2]string{"WARNING", fmt.Sprintf("askpass was not started by sudo (parent %s, euid %d)", sanitize(r.ParentName), r.ParentEUID)})
	}
	if !p.Deadline.IsZero() {
		lines = append(lines, [2]string{"Expires", p.Deadline.Format("15:04:05")})
	}
	return lines
}

// IsSudo reports whether the client says it was started by a process named
// sudo running with effective UID 0. An unprivileged user can name a binary
// "sudo" but cannot give it EUID 0 without a setuid root sudo, so this tells
// accidental direct invocations apart from real sudo prompts. It is no
// defence against a client lying about it.
func IsSudo(r *protocol.Request) bool {
	return (r.ParentName == "sudo" || r.ParentName == "sudo-rs") && r.ParentEUID == 0
}

// FormatArgs renders a command line as one sanitized, shell-quoted string.
func FormatArgs(args []string) string {
	if len(args) == 0 {
		return "(unknown)"
	}
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t'\"\\$`") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts[i] = a
	}
	return sanitize(strings.Join(parts, " "))
}

// sanitize escapes control, format and invalid characters, and truncates
// to maxField runes.
func sanitize(s string) string {
	if s == "" {
		return "(none)"
	}
	var b strings.Builder
	n := 0
	for i, w := 0, 0; i < len(s); i += w {
		if n == maxField {
			b.WriteString("…")
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		w = size
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}
