// Package server accepts askpass requests over mTLS and answers each with
// whatever the human types into a dialog.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/lllamnyp/askpass/internal/dialog"
	"github.com/lllamnyp/askpass/internal/protocol"
)

// DefaultTimeout is how long a request waits for an answer, including time
// spent queued behind another open dialog.
const DefaultTimeout = 60 * time.Second

// ioTimeout bounds the handshake, reading the request and writing the answer.
const ioTimeout = 10 * time.Second

// Server answers askpass requests. Dialogs are shown one at a time.
type Server struct {
	TLSConfig *tls.Config
	Prompter  dialog.Prompter
	Timeout   time.Duration
	Logger    *slog.Logger

	slot chan struct{}
}

// Serve accepts connections on ln until ctx is cancelled. ln must be a plain
// listener; Serve performs the TLS handshake itself.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.TLSConfig == nil || s.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return errors.New("server TLS config must require and verify client certificates")
	}
	if s.Timeout <= 0 {
		s.Timeout = DefaultTimeout
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	s.slot = make(chan struct{}, 1)

	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	log := s.Logger.With("remote", raw.RemoteAddr().String())

	conn := tls.Server(raw, s.TLSConfig)
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		log.Warn("TLS handshake failed", "err", err)
		return
	}
	clientName := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	log = log.With("client", clientName)

	req, err := protocol.ReadRequest(conn)
	if err != nil {
		log.Warn("bad request", "err", err)
		_ = protocol.WriteResponse(conn, protocol.StatusError, []byte("bad request"))
		return
	}
	log.Info("password requested", "host", req.Host, "user", req.User, "command", dialog.FormatArgs(req.ParentArgs))

	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	// The client sends nothing more, so a read returning means it hung up
	// (sudo was interrupted, or it timed out): withdraw the dialog.
	_ = conn.SetDeadline(time.Time{})
	go func() {
		var b [1]byte
		_, _ = conn.Read(b[:])
		cancel()
	}()

	status, payload, err := s.ask(ctx, &dialog.Prompt{
		ClientName: clientName,
		RemoteAddr: raw.RemoteAddr().String(),
		Request:    req,
		Deadline:   deadline,
	})
	defer clear(payload)
	if status == protocol.StatusError {
		log.Warn("request failed", "err", err)
	} else {
		log.Info("request finished", "outcome", status.String())
	}

	_ = conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	if err := protocol.WriteResponse(conn, status, payload); err != nil {
		log.Warn("sending answer failed", "err", err)
		return
	}
	_ = conn.CloseWrite()
}

// ask waits for the dialog slot, then prompts. On success the payload is
// the password; otherwise it is a reason and err says what went wrong.
func (s *Server) ask(ctx context.Context, p *dialog.Prompt) (protocol.Status, []byte, error) {
	select {
	case s.slot <- struct{}{}:
		defer func() { <-s.slot }()
	case <-ctx.Done():
		return statusFor(ctx.Err())
	}
	pw, err := s.Prompter.Ask(ctx, p)
	if err != nil {
		clear(pw)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return statusFor(err)
	}
	return protocol.StatusOK, pw, nil
}

func statusFor(err error) (protocol.Status, []byte, error) {
	switch {
	case errors.Is(err, dialog.ErrDenied):
		return protocol.StatusDenied, []byte("denied"), err
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.StatusTimeout, []byte("no answer before the timeout"), err
	case errors.Is(err, context.Canceled):
		return protocol.StatusError, []byte("request cancelled"), err
	}
	return protocol.StatusError, []byte("dialog failed"), err
}
