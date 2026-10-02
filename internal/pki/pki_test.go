package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func verify(cert *x509.Certificate, ca *CA, usage x509.ExtKeyUsage, name string) error {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: name})
	return err
}

func TestIssue(t *testing.T) {
	ca, _, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := NewCA("other CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	srvPEM, _, err := ca.IssueServer("srv", []net.IP{net.ParseIP("10.99.0.2")}, nil, LeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	srv := parseCert(t, srvPEM)
	if err := verify(srv, ca, x509.ExtKeyUsageServerAuth, "10.99.0.2"); err != nil {
		t.Errorf("server cert does not verify: %v", err)
	}
	if err := verify(srv, ca, x509.ExtKeyUsageServerAuth, "10.99.0.3"); err == nil {
		t.Error("server cert valid for wrong IP")
	}
	if err := verify(srv, ca, x509.ExtKeyUsageClientAuth, ""); err == nil {
		t.Error("server cert usable as client cert")
	}
	if err := verify(srv, other, x509.ExtKeyUsageServerAuth, "10.99.0.2"); err == nil {
		t.Error("server cert verifies against unrelated CA")
	}
	if !srv.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("leaf outlives CA: %v > %v", srv.NotAfter, ca.Cert.NotAfter)
	}

	cliPEM, _, err := ca.IssueClient("vps", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cli := parseCert(t, cliPEM)
	if cli.Subject.CommonName != "vps" {
		t.Errorf("CN = %q", cli.Subject.CommonName)
	}
	if err := verify(cli, ca, x509.ExtKeyUsageClientAuth, ""); err != nil {
		t.Errorf("client cert does not verify: %v", err)
	}
	if err := verify(cli, ca, x509.ExtKeyUsageServerAuth, ""); err == nil {
		t.Error("client cert usable as server cert")
	}

	if _, _, err := ca.IssueServer("srv", nil, nil, time.Hour); err == nil {
		t.Error("server cert without names issued")
	}
}

func TestSignCSR(t *testing.T) {
	ca, _, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := NewClientKeyAndCSR("vps")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.SignClientCSR(csrPEM, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, certPEM)
	if cert.Subject.CommonName != "vps" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if err := verify(cert, ca, x509.ExtKeyUsageClientAuth, ""); err != nil {
		t.Error(err)
	}
	certPEM, err = ca.SignClientCSR(csrPEM, "renamed", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cn := parseCert(t, certPEM).Subject.CommonName; cn != "renamed" {
		t.Errorf("CN override ignored: %q", cn)
	}
	if _, err := ca.SignClientCSR([]byte("garbage"), "", time.Hour); err == nil {
		t.Error("garbage CSR signed")
	}
}

func TestLoadCAAndWriteNew(t *testing.T) {
	dir := t.TempDir()
	ca, keyPEM, err := NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := WriteNew(certPath, ca.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(keyPath, []byte("x"), 0o600); err == nil {
		t.Error("WriteNew overwrote an existing file")
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", st.Mode().Perm())
	}

	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cliPEM, cliKey, err := loaded.IssueClient("vps", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(parseCert(t, cliPEM), ca, x509.ExtKeyUsageClientAuth, ""); err != nil {
		t.Error(err)
	}

	// A leaf certificate must not load as a CA.
	leafCert, leafKey := filepath.Join(dir, "leaf.crt"), filepath.Join(dir, "leaf.key")
	_ = WriteNew(leafCert, cliPEM, 0o644)
	_ = WriteNew(leafKey, cliKey, 0o600)
	if _, err := LoadCA(leafCert, leafKey); err == nil {
		t.Error("leaf certificate loaded as CA")
	}
}
