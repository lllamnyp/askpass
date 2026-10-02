package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lllamnyp/askpass/internal/client"
	"github.com/lllamnyp/askpass/internal/dialog"
	"github.com/lllamnyp/askpass/internal/pki"
	"github.com/lllamnyp/askpass/internal/protocol"
)

// fakePrompter answers every prompt by calling fn.
type fakePrompter struct {
	fn    func(ctx context.Context, p *dialog.Prompt) ([]byte, error)
	calls atomic.Int32
}

func (f *fakePrompter) Ask(ctx context.Context, p *dialog.Prompt) ([]byte, error) {
	f.calls.Add(1)
	return f.fn(ctx, p)
}

// testPKI holds file paths for one CA and certificates issued from it.
type testPKI struct {
	dir string
	ca  *pki.CA
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	ca, keyPEM, err := pki.NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, "ca.crt", ca.CertPEM)
	write(t, dir, "ca.key", keyPEM)
	return &testPKI{dir: dir, ca: ca}
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *testPKI) server(t *testing.T, ip string) *tls.Config {
	t.Helper()
	certPEM, keyPEM, err := p.ca.IssueServer("srv", []net.IP{net.ParseIP(ip)}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pki.ServerTLSConfig(filepath.Join(p.dir, "ca.crt"),
		write(t, p.dir, "server.crt", certPEM), write(t, p.dir, "server.key", keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// client returns a client TLS config presenting a cert from p and trusting
// the CA of trust.
func (p *testPKI) client(t *testing.T, name string, trust *testPKI) *tls.Config {
	t.Helper()
	certPEM, keyPEM, err := p.ca.IssueClient(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pki.ClientTLSConfig(filepath.Join(trust.dir, "ca.crt"),
		write(t, p.dir, name+".crt", certPEM), write(t, p.dir, name+".key", keyPEM), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// start runs a server on a loopback port and returns its address.
func start(t *testing.T, tlsConfig *tls.Config, pr dialog.Prompter, timeout time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		TLSConfig: tlsConfig,
		Prompter:  pr,
		Timeout:   timeout,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

func request() *protocol.Request {
	return &protocol.Request{Version: protocol.Version, Host: "vps", User: "agent", Prompt: "[sudo] password: ", ParentArgs: []string{"sudo", "-A", "true"}}
}

func ask(t *testing.T, cfg *tls.Config, addr string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return client.Ask(ctx, cfg, addr, request())
}

func answer(pw string) *fakePrompter {
	return &fakePrompter{fn: func(context.Context, *dialog.Prompt) ([]byte, error) { return []byte(pw), nil }}
}

func TestPasswordRelayed(t *testing.T) {
	p := newPKI(t)
	var got *dialog.Prompt
	pr := &fakePrompter{fn: func(_ context.Context, pp *dialog.Prompt) ([]byte, error) {
		got = pp
		return []byte("hunter2"), nil
	}}
	addr := start(t, p.server(t, "127.0.0.1"), pr, time.Minute)
	cfg := p.client(t, "vps-cert", p)

	pw, err := ask(t, cfg, addr)
	if err != nil {
		t.Fatal(err)
	}
	if string(pw) != "hunter2" {
		t.Errorf("password %q", pw)
	}
	if got.ClientName != "vps-cert" || got.Request.Prompt != "[sudo] password: " || got.Request.ParentArgs[2] != "true" {
		t.Errorf("prompt %+v / %+v", got, got.Request)
	}
	if time.Until(got.Deadline) <= 0 || time.Until(got.Deadline) > time.Minute {
		t.Errorf("deadline %v", got.Deadline)
	}

	// No caching: every request prompts again.
	if _, err := ask(t, cfg, addr); err != nil {
		t.Fatal(err)
	}
	if n := pr.calls.Load(); n != 2 {
		t.Errorf("prompted %d times for 2 requests", n)
	}
}

func TestDeniedAndTimeout(t *testing.T) {
	p := newPKI(t)
	cfg := p.client(t, "vps", p)

	deny := &fakePrompter{fn: func(context.Context, *dialog.Prompt) ([]byte, error) { return nil, dialog.ErrDenied }}
	_, err := ask(t, cfg, start(t, p.server(t, "127.0.0.1"), deny, time.Minute))
	if re, ok := errors.AsType[*client.RequestError](err); !ok || re.Status != protocol.StatusDenied {
		t.Errorf("deny: got %v", err)
	}

	var cancelled atomic.Bool
	hang := &fakePrompter{fn: func(ctx context.Context, _ *dialog.Prompt) ([]byte, error) {
		<-ctx.Done()
		cancelled.Store(true)
		return nil, ctx.Err()
	}}
	_, err = ask(t, cfg, start(t, p.server(t, "127.0.0.1"), hang, 200*time.Millisecond))
	if re, ok := errors.AsType[*client.RequestError](err); !ok || re.Status != protocol.StatusTimeout {
		t.Errorf("timeout: got %v", err)
	}
	if !cancelled.Load() {
		t.Error("dialog not cancelled on timeout")
	}

	broken := &fakePrompter{fn: func(context.Context, *dialog.Prompt) ([]byte, error) { return nil, errors.New("no display") }}
	_, err = ask(t, cfg, start(t, p.server(t, "127.0.0.1"), broken, time.Minute))
	if re, ok := errors.AsType[*client.RequestError](err); !ok || re.Status != protocol.StatusError {
		t.Errorf("dialog error: got %v", err)
	}
}

func TestClientHangupWithdrawsDialog(t *testing.T) {
	p := newPKI(t)
	withdrawn := make(chan struct{})
	pr := &fakePrompter{fn: func(ctx context.Context, _ *dialog.Prompt) ([]byte, error) {
		<-ctx.Done()
		close(withdrawn)
		return nil, ctx.Err()
	}}
	addr := start(t, p.server(t, "127.0.0.1"), pr, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := client.Ask(ctx, p.client(t, "vps", p), addr, request()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("client: got %v", err)
	}
	select {
	case <-withdrawn:
	case <-time.After(5 * time.Second):
		t.Error("dialog still open after client hung up")
	}
}

func TestDialogsSerialized(t *testing.T) {
	p := newPKI(t)
	var open, maxOpen atomic.Int32
	pr := &fakePrompter{fn: func(context.Context, *dialog.Prompt) ([]byte, error) {
		n := open.Add(1)
		for {
			m := maxOpen.Load()
			if n <= m || maxOpen.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		open.Add(-1)
		return []byte("pw"), nil
	}}
	addr := start(t, p.server(t, "127.0.0.1"), pr, time.Minute)
	cfg := p.client(t, "vps", p)

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := ask(t, cfg, addr); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if m := maxOpen.Load(); m != 1 {
		t.Errorf("%d dialogs open at once", m)
	}
}

func TestMutualAuthentication(t *testing.T) {
	p := newPKI(t)
	rogue := newPKI(t)
	pr := answer("secret")
	addr := start(t, p.server(t, "127.0.0.1"), pr, time.Minute)

	cases := map[string]*tls.Config{
		// Client cert from another CA: the server must refuse it.
		"foreign client cert": rogue.client(t, "vps", p),
		// Client that does not trust the server's CA must refuse to talk.
		"untrusted server": p.client(t, "vps", rogue),
	}
	noCert := p.client(t, "vps", p).Clone()
	noCert.Certificates = nil
	cases["no client cert"] = noCert
	wrongName := p.client(t, "vps", p).Clone()
	wrongName.ServerName = "10.99.0.2"
	cases["server cert for another address"] = wrongName

	for name, cfg := range cases {
		if pw, err := ask(t, cfg, addr); err == nil {
			t.Errorf("%s: got password %q", name, pw)
		}
	}
	if n := pr.calls.Load(); n != 0 {
		t.Errorf("unauthenticated requests reached the dialog %d times", n)
	}
}

func TestServerTLSConfigRequired(t *testing.T) {
	p := newPKI(t)
	cfg := p.server(t, "127.0.0.1").Clone()
	cfg.ClientAuth = tls.VerifyClientCertIfGiven
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{TLSConfig: cfg, Prompter: answer("x")}
	if err := s.Serve(context.Background(), ln); err == nil {
		t.Error("served without required client certificates")
	}
}

func TestUnreachableServer(t *testing.T) {
	p := newPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := ask(t, p.client(t, "vps", p), addr); err == nil {
		t.Error("no error for unreachable server")
	}
}
