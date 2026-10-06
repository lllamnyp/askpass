package dialog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lllamnyp/askpass/internal/protocol"
)

// Zenity prompts with zenity: first a read-only text window showing the
// script or long command line that ran sudo, if there is one, then a dialog
// with the request's details and a hidden password field.
type Zenity struct {
	// Path is the zenity executable; empty means "zenity" from PATH.
	Path string
}

// Ask implements Prompter.
func (z *Zenity) Ask(ctx context.Context, p *Prompt) ([]byte, error) {
	if err := CheckRequest(p.Request); err != nil {
		return nil, err
	}
	path := z.Path
	if path == "" {
		path = "zenity"
	}
	if review := DescribeInvoker(p.Request.InvokerArgs).Review; review != "" {
		cmd := exec.CommandContext(ctx, path, reviewArgs(p, time.Now())...)
		cmd.WaitDelay = 2 * time.Second
		cmd.Stdin = strings.NewReader(review + "\n")
		if err := exitError(ctx, cmd.Run()); err != nil {
			return nil, err
		}
	}

	cmd := exec.CommandContext(ctx, path, zenityArgs(p, time.Now())...)
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting zenity: %w", err)
	}

	// Read into one fixed buffer rather than a growing bytes.Buffer, so the
	// password is never left behind in a discarded reallocation.
	buf := make([]byte, protocol.MaxPayload+2)
	defer clear(buf)
	n, readErr := io.ReadFull(stdout, buf)
	if readErr == nil {
		// Too long to be a password we can relay; drain and fail.
		_, _ = io.Copy(io.Discard, stdout)
	}
	if err := exitError(ctx, cmd.Wait()); err != nil {
		return nil, err
	}
	if readErr == nil {
		return nil, errors.New("password too long")
	}
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("reading zenity output: %w", readErr)
	}
	out := buf[:n]
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		// An empty Send counts as Deny: it is almost always a stray Enter.
		return nil, ErrDenied
	}
	return append([]byte(nil), out...), nil
}

// exitError maps how a zenity run ended to Ask's errors.
func exitError(ctx context.Context, waitErr error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok {
		switch exitErr.ExitCode() {
		case 1:
			return ErrDenied
		case 5:
			return context.DeadlineExceeded
		}
	}
	if waitErr != nil {
		return fmt.Errorf("zenity failed: %w", waitErr)
	}
	return nil
}

// reviewArgs shows the text read from stdin in a read-only, selectable text
// view. Unlike --entry --text, it is shown verbatim, with no escape decoding.
func reviewArgs(p *Prompt, now time.Time) []string {
	args := []string{
		"--text-info",
		"--title=askpass: review what ran sudo on " + sanitize(p.Request.Host),
		"--font=monospace",
		"--width=900",
		"--height=600",
		"--ok-label=Continue",
		"--cancel-label=Deny",
	}
	return append(args, timeoutArgs(p, now)...)
}

func timeoutArgs(p *Prompt, now time.Time) []string {
	if p.Deadline.IsZero() {
		return nil
	}
	secs := max(int(p.Deadline.Sub(now).Seconds()), 1)
	return []string{"--timeout=" + strconv.Itoa(secs)}
}

// wrapWidth is where dialog lines are broken: zenity's labels don't wrap.
const wrapWidth = 72

func zenityArgs(p *Prompt, now time.Time) []string {
	var warnings, details []string
	for _, l := range p.Lines() {
		line := wrap(l[0]+": "+l[1], wrapWidth, "    ")
		if l[0] == "WARNING" {
			warnings = append(warnings, line)
		} else {
			details = append(details, line)
		}
	}
	text := strings.Join(append(append([]string{"sudo password requested"}, warnings...), details...), "\n")
	args := []string{
		"--entry",
		"--hide-text",
		"--title=askpass: sudo on " + sanitize(p.Request.Host),
		"--text=" + escapeLabel(text),
		"--ok-label=Send",
		"--cancel-label=Deny",
	}
	return append(args, timeoutArgs(p, now)...)
}

// wrap breaks s into lines of at most width runes, at spaces where possible,
// prefixing continuation lines with indent.
func wrap(s string, width int, indent string) string {
	var lines []string
	r := []rune(s)
	for limit := width; len(r) > limit; limit = width - len([]rune(indent)) {
		cut := limit
		for i := limit; i > limit/2; i-- {
			if r[i] == ' ' {
				cut = i
				break
			}
		}
		lines = append(lines, string(r[:cut]))
		r = []rune(strings.TrimLeft(string(r[cut:]), " "))
	}
	lines = append(lines, string(r))
	return strings.Join(lines, "\n"+indent)
}

// labelEscaper escapes text for zenity --entry --text, which zenity passes
// through g_strcompress (decoding C escapes such as \n and \000) and then
// shows as a plain label where "_" marks a mnemonic.
var labelEscaper = strings.NewReplacer(`\`, `\\`, "_", "__")

func escapeLabel(s string) string {
	return labelEscaper.Replace(s)
}
