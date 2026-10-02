package pki

import (
	"crypto/tls"
	"fmt"
)

// ServerTLSConfig builds a TLS 1.3 server config that presents certPath/keyPath
// and requires a client certificate signed by the CA in caPath.
func ServerTLSConfig(caPath, certPath, keyPath string) (*tls.Config, error) {
	pool, err := LoadPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// ClientTLSConfig builds a TLS 1.3 client config that presents certPath/keyPath
// and accepts only a server certificate signed by the CA in caPath and valid
// for serverName.
func ClientTLSConfig(caPath, certPath, keyPath, serverName string) (*tls.Config, error) {
	pool, err := LoadPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
}
