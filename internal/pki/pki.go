// Package pki creates the private CA askpass uses for mTLS and issues server
// and client certificates from it. Keys it generates are ECDSA P-256 in PKCS#8 PEM.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// Default validity periods.
const (
	CAValidity   = 10 * 365 * 24 * time.Hour
	LeafValidity = 2 * 365 * 24 * time.Hour
)

// clockSkew backdates NotBefore so freshly issued certs are valid on a peer
// whose clock runs slightly behind.
const clockSkew = 5 * time.Minute

// CA is a loaded certificate authority able to sign leaf certificates.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// NewCA generates a self-signed CA certificate and key.
func NewCA(commonName string, validity time.Duration) (*CA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return &CA{Cert: cert, CertPEM: encodeCert(der), key: key}, keyPEM, nil
}

// LoadCA reads a CA certificate and its private key from PEM files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", certPath)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key cannot sign")
	}
	return &CA{Cert: cert, CertPEM: encodeCert(pair.Certificate[0]), key: signer}, nil
}

// IssueServer issues a server certificate valid for the given IP addresses
// and DNS names.
func (ca *CA) IssueServer(commonName string, ips []net.IP, dnsNames []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if len(ips) == 0 && len(dnsNames) == 0 {
		return nil, nil, errors.New("server certificate needs at least one IP address or DNS name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := ca.leafTemplate(commonName, validity, x509.ExtKeyUsageServerAuth)
	tmpl.IPAddresses = ips
	tmpl.DNSNames = dnsNames
	certPEM, err = ca.sign(tmpl, key.Public())
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return certPEM, keyPEM, err
}

// IssueClient generates a client key and certificate.
func (ca *CA) IssueClient(commonName string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certPEM, err = ca.sign(ca.leafTemplate(commonName, validity, x509.ExtKeyUsageClientAuth), key.Public())
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return certPEM, keyPEM, err
}

// SignClientCSR issues a client certificate for the public key in a PEM
// certificate signing request. Only the CSR's key and, unless commonName is
// non-empty, its subject CN are used; requested extensions are ignored.
func (ca *CA) SignClientCSR(csrPEM []byte, commonName string, validity time.Duration) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("no PEM CERTIFICATE REQUEST found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if err := checkKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if commonName == "" {
		commonName = csr.Subject.CommonName
	}
	if commonName == "" {
		return nil, errors.New("CSR has no common name; pass one explicitly")
	}
	return ca.sign(ca.leafTemplate(commonName, validity, x509.ExtKeyUsageClientAuth), csr.PublicKey)
}

// checkKey accepts ECDSA P-256/P-384/P-521, Ed25519 and RSA keys of at
// least 2048 bits.
func checkKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return nil
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key too short (%d bits, need 2048)", k.N.BitLen())
		}
		return nil
	}
	return fmt.Errorf("unsupported public key type %T", pub)
}

// NewClientKeyAndCSR generates a client key and a CSR for it.
func NewClientKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// LoadPool reads a PEM CA bundle into a fresh pool containing only those
// certificates, never the system roots.
func LoadPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// WriteNew writes data to a file that must not already exist, so issuing
// never silently replaces a key or certificate.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (ca *CA) leafTemplate(commonName string, validity time.Duration, usage x509.ExtKeyUsage) *x509.Certificate {
	now := time.Now()
	notAfter := now.Add(validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
}

func (ca *CA) sign(tmpl *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return encodeCert(der), nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
