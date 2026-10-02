// Package protocol defines the wire format spoken between the askpass client
// and server over an established mTLS connection.
//
// The client sends exactly one Request as a single JSON line. The server
// answers with exactly one binary response frame and closes the connection:
//
//	+--------+----------------+-----------------+
//	| status | length (BE u16)| payload         |
//	| 1 byte | 2 bytes        | length bytes    |
//	+--------+----------------+-----------------+
//
// For StatusOK the payload is the password; for every other status it is a
// short human-readable reason. The response is binary rather than JSON so the
// password lands in a single []byte the caller owns and can zero, instead of
// passing through string conversions and encoder buffers.
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version carried in every request.
const Version = 1

const (
	// MaxRequestSize bounds the request line, so a client cannot make the
	// server buffer unbounded input.
	MaxRequestSize = 64 << 10
	// MaxPayload bounds a response payload (password or reason).
	MaxPayload = 4096
)

// Status is the first byte of a response frame.
type Status byte

const (
	StatusOK      Status = 1
	StatusDenied  Status = 2
	StatusTimeout Status = 3
	StatusError   Status = 4
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusDenied:
		return "denied"
	case StatusTimeout:
		return "timeout"
	case StatusError:
		return "error"
	}
	return fmt.Sprintf("status(%d)", byte(s))
}

// Request describes who is asking for the password. Every field is asserted
// by the client and is informational only: the server authenticates the
// client by its certificate, not by anything in here.
type Request struct {
	Version int    `json:"v"`
	Host    string `json:"host"`
	User    string `json:"user"`
	UID     int    `json:"uid"`
	// Prompt is the prompt text sudo passed to the askpass program.
	Prompt string `json:"prompt"`
	// ParentName, ParentEUID and ParentArgs describe the process that ran
	// askpass: normally sudo, whose arguments are the command being
	// elevated. ParentEUID is -1 when unknown.
	ParentName string   `json:"parent_name,omitempty"`
	ParentEUID int      `json:"parent_euid"`
	ParentArgs []string `json:"parent_args,omitempty"`
	// InvokerArgs is the command line of the parent's parent: whatever ran
	// sudo, such as a shell or an agent's tool runner.
	InvokerArgs []string `json:"invoker_args,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
}

// WriteRequest encodes req as one JSON line.
func WriteRequest(w io.Writer, req *Request) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxRequestSize {
		return fmt.Errorf("request too large (%d bytes)", len(b))
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadRequest reads and decodes one JSON request line of at most
// MaxRequestSize bytes.
func ReadRequest(r io.Reader) (*Request, error) {
	line, err := bufio.NewReader(io.LimitReader(r, MaxRequestSize)).ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("reading request: truncated or larger than the size limit")
		}
		return nil, fmt.Errorf("reading request: %w", err)
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("decoding request: %w", err)
	}
	if req.Version != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", req.Version)
	}
	return &req, nil
}

// WriteResponse writes one response frame in a single Write call.
func WriteResponse(w io.Writer, status Status, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("payload too large (%d bytes)", len(payload))
	}
	frame := make([]byte, 3+len(payload))
	defer clear(frame)
	frame[0] = byte(status)
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(payload)))
	copy(frame[3:], payload)
	_, err := w.Write(frame)
	return err
}

// ReadResponse reads one response frame. The returned payload is a fresh
// slice owned by the caller, who should clear it once done.
func ReadResponse(r io.Reader) (Status, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("reading response header: %w", err)
	}
	status := Status(hdr[0])
	n := int(binary.BigEndian.Uint16(hdr[1:3]))
	if n > MaxPayload {
		return 0, nil, fmt.Errorf("response payload too large (%d bytes)", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		clear(payload)
		return 0, nil, fmt.Errorf("reading response payload: %w", err)
	}
	return status, payload, nil
}
