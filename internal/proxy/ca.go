package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertificateAuthority manages a dynamic Root CA and signs per-host certificates for HTTPS interception.
type CertificateAuthority struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      []byte
	caCertPath string
	certCache  sync.Map
}

// NewCertificateAuthority creates a new dynamic Root CA in the specified directory.
func NewCertificateAuthority(tempDir string) (*CertificateAuthority, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating CA serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "iam-shrink Root CA",
			Organization: []string{"iam-shrink Local Proxy"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	caCertPath := filepath.Join(tempDir, "iam-shrink-ca.pem")
	if err := os.WriteFile(caCertPath, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing CA cert to %s: %w", caCertPath, err)
	}

	return &CertificateAuthority{
		caCert:     cert,
		caKey:      key,
		caPEM:      certPEM,
		caCertPath: caCertPath,
	}, nil
}

// CertPath returns the filesystem path to the Root CA PEM bundle.
func (ca *CertificateAuthority) CertPath() string {
	return ca.caCertPath
}

// SignHost generates or retrieves a cached TLS Certificate for a given hostname.
func (ca *CertificateAuthority) SignHost(host string) (*tls.Certificate, error) {
	if val, ok := ca.certCache.Load(host); ok {
		cert := val.(*tls.Certificate)
		return cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating host key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing host cert for %s: %w", host, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing signed TLS keypair: %w", err)
	}

	ca.certCache.Store(host, &tlsCert)
	return &tlsCert, nil
}
