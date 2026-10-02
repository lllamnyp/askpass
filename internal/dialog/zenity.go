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
	return append([]byte(nil), out...), nil
}

func zenityArgs(p *Prompt, now time.Time) []string {
	var text strings.Builder
	text.WriteString("<b>sudo password requested</b>\n")
	for _, l := range p.Lines() {
		label := escapeMarkup(l[0])
		if l[0] == "WARNING" {
			label = `<span foreground="red"><b>` + label + `</b></span>`
		}
		fmt.Fprintf(&text, "\n<b>%s:</b> %s", label, escapeMarkup(l[1]))
	}
	args := []string{
		"--forms",
		"--title=askpass: sudo on " + sanitize(p.Request.Host),
		"--text=" + text.String(),
		"--add-password=Password",
		"--ok-label=Send",
		"--cancel-label=Deny",
		"--width=560",
	}
	if !p.Deadline.IsZero() {
		secs := max(int(p.Deadline.Sub(now).Seconds()), 1)
		args = append(args, "--timeout="+strconv.Itoa(secs))
	}
	return args
}

// escapeMarkup escapes text for Pango markup, which zenity --text renders.
func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}
