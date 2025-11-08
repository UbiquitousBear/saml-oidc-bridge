package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
)

type KeyStore struct {
	activeID string
	signers  map[string]tls.Certificate
	certsDER map[string][]byte
}

func NewKeyStore(c config.Crypto) (*KeyStore, error) {
	ks := &KeyStore{
		activeID: c.ActiveKey,
		signers:  map[string]tls.Certificate{},
		certsDER: map[string][]byte{},
	}
	for _, k := range c.Keys {
		cert, priv, err := parseKeypair(k.CertPEM, k.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k.ID, err)
		}
		ks.certsDER[k.ID] = cert.Raw
		if priv != nil {
			ks.signers[k.ID] = tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}
		}
	}
	if _, ok := ks.signers[ks.activeID]; !ok {
		return nil, errors.New("active signing key not available (missing or no private key)")
	}
	return ks, nil
}

func (ks *KeyStore) Active() tls.Certificate { return ks.signers[ks.activeID] }
func (ks *KeyStore) AllCertsDER() [][]byte {
	out := make([][]byte, 0, len(ks.certsDER))
	for _, der := range ks.certsDER {
		out = append(out, der)
	}
	return out
}

func parseKeypair(certPEM, keyPEM string) (*x509.Certificate, interface{}, error) {
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil {
		return nil, nil, errors.New("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	var priv interface{}
	if keyPEM != "" {
		kb, _ := pem.Decode([]byte(keyPEM))
		if kb == nil {
			return nil, nil, errors.New("invalid key pem")
		}
		priv, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			priv, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return cert, priv, nil
}
