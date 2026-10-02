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

// Zenity prompts with a GTK zenity forms dialog holding one password field.
type Zenity struct {
	// Path is the zenity executable; empty means "zenity" from PATH.
	Path string
}

// Ask implements Prompter.
func (z *Zenity) Ask(ctx context.Context, p *Prompt) ([]byte, error) {
	path := z.Path
	if path == "" {
		path = "zenity"
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
	waitErr := cmd.Wait()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok {
		switch exitErr.ExitCode() {
		case 1:
			return nil, ErrDenied
		case 5:
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("zenity failed: %w", waitErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("zenity failed: %w", waitErr)
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
	if !p.Deadline.IsZero() {
		secs := max(int(p.Deadline.Sub(now).Seconds()), 1)
		args = append(args, "--timeout="+strconv.Itoa(secs))
	}
	return args
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
