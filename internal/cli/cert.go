package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"shamilnunhuck/saml-oidc-bridge/internal/config"
)

type rotateOpts struct {
	ConfigPath string
	ID         string
	Algo       string
	Days       int
	CN         string
	Org        string
	OutK8s     string
	ActiveOnly bool
}

func RunCert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	var ro rotateOpts
	fs.StringVar(&ro.ConfigPath, "config", "example.config.yaml", "path to config yaml")
	fs.StringVar(&ro.ID, "id", "", "key id (e.g. k-2025-10)")
	fs.StringVar(&ro.Algo, "algo", "rsa3072", "rsa2048|rsa3072|rsa4096|p256|p384")
	fs.IntVar(&ro.Days, "days", 825, "validity in days")
	fs.StringVar(&ro.CN, "cn", "id.example.com", "certificate CN")
	fs.StringVar(&ro.Org, "org", "YourOrg", "certificate O")
	fs.StringVar(&ro.OutK8s, "k8s-secret-out", "", "write a Kubernetes Secret manifest to this path")
	fs.BoolVar(&ro.ActiveOnly, "active-only", false, "only set active_key to -id (no new cert)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if ro.ID == "" {
		return errors.New("missing -id")
	}

	cfg, raw, err := loadConfig(ro.ConfigPath)
	if err != nil {
		return err
	}

	if ro.ActiveOnly {
		cfg.Crypto.ActiveKey = ro.ID
		return saveConfig(ro.ConfigPath, raw, cfg)
	}

	certPEM, keyPEM, notAfter, err := genSelfSigned(ro)
	if err != nil {
		return err
	}

	cfg.Crypto.Keys = append(cfg.Crypto.Keys, config.KeyPair{
		ID:       ro.ID,
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
		NotAfter: notAfter.UTC(),
	})
	cfg.Crypto.ActiveKey = ro.ID

	if err := saveConfig(ro.ConfigPath, raw, cfg); err != nil {
		return err
	}
	if ro.OutK8s != "" {
		if err := os.WriteFile(ro.OutK8s, []byte(k8sSecretYAML(ro, certPEM, keyPEM)), 0o600); err != nil {
			return fmt.Errorf("write secret: %w", err)
		}
	}
	fmt.Printf("OK: generated %s (algo=%s, not_after=%s) and set active_key\n", ro.ID, ro.Algo, notAfter.UTC().Format(time.RFC3339))
	return nil
}

func genSelfSigned(ro rotateOpts) (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	nb := time.Now().Add(-5 * time.Minute)
	na := nb.Add(time.Duration(ro.Days) * 24 * time.Hour)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         ro.CN,
			Organization:       []string{ro.Org},
			OrganizationalUnit: []string{"SAML Signing"},
		},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	var der []byte
	var keyPKCS8 []byte

	switch strings.ToLower(ro.Algo) {
	case "rsa2048", "rsa3072", "rsa4096":
		bits := 2048
		if ro.Algo == "rsa3072" {
			bits = 3072
		}
		if ro.Algo == "rsa4096" {
			bits = 4096
		}
		priv, e := rsa.GenerateKey(rand.Reader, bits)
		if e != nil {
			return nil, nil, time.Time{}, e
		}
		der, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		keyPKCS8, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
	case "p256", "p384":
		curve := elliptic.P256()
		if ro.Algo == "p384" {
			curve = elliptic.P384()
		}
		priv, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			return nil, nil, time.Time{}, e
		}
		der, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		keyPKCS8, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
	default:
		return nil, nil, time.Time{}, fmt.Errorf("unknown -algo %q", ro.Algo)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPKCS8})
	return certPEM, keyPEM, na, nil
}

func loadConfig(path string) (*config.Config, *yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, nil, err
	}
	var c config.Config
	if err := root.Decode(&c); err != nil {
		return nil, nil, err
	}
	return &c, &root, nil
}

func saveConfig(path string, _ *yaml.Node, c *config.Config) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return err
	}
	_ = enc.Close()
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func k8sSecretYAML(ro rotateOpts, certPEM, keyPEM []byte) string {
	name := strings.ToLower(strings.ReplaceAll(ro.ID, "_", "-"))
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: saml-signing-%s
type: Opaque
stringData:
  cert.pem: |-
%s
  key.pem: |-
%s
`, name, indent(string(certPEM), 4), indent(string(keyPEM), 4))
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}
