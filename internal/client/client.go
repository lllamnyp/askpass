package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/lllamnyp/askpass/internal/protocol"
)

// RequestError is returned when the server answered but did not provide a
// password.
type RequestError struct {
	Status protocol.Status
	Reason string
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%s: %s", e.Status, e.Reason)
}

// Ask sends req to the server and returns the password. The returned slice
// belongs to the caller, who must clear it.
func Ask(ctx context.Context, tlsConfig *tls.Config, addr string, req *protocol.Request) ([]byte, error) {
	d := &tls.Dialer{Config: tlsConfig}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	conn := c.(*tls.Conn)
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := protocol.WriteRequest(conn, req); err != nil {
		return nil, wrapCtx(ctx, fmt.Errorf("sending request: %w", err))
	}
	status, payload, err := protocol.ReadResponse(conn)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if status != protocol.StatusOK {
		reason := string(payload)
		clear(payload)
		return nil, &RequestError{Status: status, Reason: reason}
	}
	return payload, nil
}

func wrapCtx(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w (%v)", ctx.Err(), err)
	}
	return err
}

// Describe builds a request describing this process and the sudo invocation
// that started it.
func Describe(prompt string) *protocol.Request {
	req := &protocol.Request{
		Version: protocol.Version,
		Prompt:  prompt,
		UID:     os.Getuid(),
	}
	req.Host, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		req.User = u.Username
	}
	req.Cwd, _ = os.Getwd()

	ppid := os.Getppid()
	req.ParentArgs = cmdline(ppid)
	req.ParentEUID = -1
	if st, err := readStatus(ppid); err == nil {
		req.ParentName = st.name
		req.ParentEUID = st.euid
		if st.ppid > 0 {
			req.InvokerArgs = cmdline(st.ppid)
		}
	}
	return req
}

func procPath(pid int, name string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + name
}

func cmdline(pid int) []string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
}

type procStatus struct {
	name string
	ppid int
	euid int
}

// readStatus reads /proc/<pid>/status, which unlike /proc/<pid>/exe stays
// readable when the process is setuid sudo.
func readStatus(pid int) (*procStatus, error) {
	b, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return nil, err
	}
	return parseStatus(string(b))
}

func parseStatus(s string) (*procStatus, error) {
	st := &procStatus{euid: -1}
	var haveName, havePPid, haveUid bool
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			st.name, haveName = v, true
		case "PPid":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("bad PPid %q", v)
			}
			st.ppid, havePPid = n, true
		case "Uid":
			// Real, effective, saved set, filesystem.
			f := strings.Fields(v)
			if len(f) < 2 {
				return nil, fmt.Errorf("bad Uid %q", v)
			}
			n, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("bad Uid %q", v)
			}
			st.euid, haveUid = n, true
		}
	}
	if !haveName || !havePPid || !haveUid {
		return nil, errors.New("incomplete status")
	}
	return st, nil
}
