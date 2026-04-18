// ─────────────────────────────────────────────────────────────────────────────
// Package auth — Ephemeral mTLS Certificate Manager
// ─────────────────────────────────────────────────────────────────────────────
// Generates RSA 2048 self-signed TLS 1.3 certificates entirely in memory.
// No private key or certificate ever touches the filesystem. A background
// ticker rotates the certificate every hour for forward secrecy.
//
// Thread Safety:
//   - The current certificate is guarded by a sync.RWMutex.
//   - TLS handshakes acquire a read lock (non-blocking for concurrency).
//   - Rotation acquires a write lock (blocks only during the swap).
//
// ─────────────────────────────────────────────────────────────────────────────
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// rsaKeyBits — RSA key size for generated certificates.
	rsaKeyBits = 2048

	// certLifetime — how long each generated certificate is valid for.
	// Set slightly longer than the rotation interval to avoid gaps.
	certLifetime = 2 * time.Hour

	// rotationInterval — how frequently the certificate is regenerated.
	rotationInterval = 1 * time.Hour
)

// ─────────────────────────────────────────────────────────────────────────────
// CertManager
// ─────────────────────────────────────────────────────────────────────────────
// Holds the current in-memory TLS certificate and provides a thread-safe
// accessor for the TLS handshake callback. Call StartRotation() to enable
// automatic hourly regeneration.
// ─────────────────────────────────────────────────────────────────────────────

// CertManager manages ephemeral, in-memory TLS certificates with automatic
// rotation. It implements the zero-disk-I/O requirement — no key material
// is ever written to the filesystem.
type CertManager struct {
	// mu guards access to the current certificate.
	mu sync.RWMutex

	// current is the active TLS certificate used for all handshakes.
	current *tls.Certificate

	// generation tracks how many certificates have been generated
	// (starting at 1). Useful for logging rotation events.
	generation int
}

// ─────────────────────────────────────────────────────────────────────────────
// NewCertManager — constructor
// ─────────────────────────────────────────────────────────────────────────────
// Generates the initial certificate and returns a ready-to-use CertManager.
// Returns an error only if the initial generation fails (e.g., entropy
// exhaustion on the host).
// ─────────────────────────────────────────────────────────────────────────────

func NewCertManager() (*CertManager, error) {
	cm := &CertManager{generation: 0}

	// Generate the first certificate. If this fails, the gateway cannot
	// start — surface the error immediately.
	if err := cm.rotate(); err != nil {
		return nil, fmt.Errorf("initial certificate generation failed: %w", err)
	}

	log.Printf("[AUTH] CertManager initialized — generation %d, RSA-%d, TLS 1.3",
		cm.generation, rsaKeyBits)

	return cm, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// GetTLSConfig — builds a *tls.Config wired to this CertManager
// ─────────────────────────────────────────────────────────────────────────────
// The returned config uses GetCertificate to dynamically serve the current
// certificate. This means certificate rotation is fully transparent to
// active connections — new handshakes will use the latest cert.
// ─────────────────────────────────────────────────────────────────────────────

func (cm *CertManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		// GetCertificate is called during every TLS handshake. We read-lock
		// the current cert so rotations don't cause races.
		GetCertificate: cm.getCertificate,

		// Enforce TLS 1.3 minimum — no fallback to older protocols.
		MinVersion: tls.VersionTLS13,

		// NextProtos is required for QUIC (h3) and HTTP/2 ALPN negotiation.
		NextProtos: []string{"h3", "hive-quic"},
	}
}

// getCertificate is the internal callback for tls.Config.GetCertificate.
// It acquires a read lock and returns a pointer to the current certificate.
func (cm *CertManager) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.current == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	return cm.current, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// StartRotation — background certificate renewal
// ─────────────────────────────────────────────────────────────────────────────
// Launches a goroutine that regenerates the certificate every rotationInterval
// (1 hour). The goroutine exits cleanly when the provided context is cancelled,
// which happens during gateway shutdown.
// ─────────────────────────────────────────────────────────────────────────────

func (cm *CertManager) StartRotation(ctx context.Context) {
	ticker := time.NewTicker(rotationInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Gateway is shutting down — stop the rotation loop.
				log.Printf("[AUTH] Certificate rotation stopped (context cancelled)")
				return

			case <-ticker.C:
				// Time to rotate. If rotation fails, log the error but keep
				// the existing certificate active — degraded is better than dead.
				if err := cm.rotate(); err != nil {
					log.Printf("[AUTH] ⚠ Certificate rotation failed: %v (keeping generation %d)",
						err, cm.generation)
				} else {
					log.Printf("[AUTH] ✓ Certificate rotated — now generation %d", cm.generation)
				}
			}
		}
	}()

	log.Printf("[AUTH] Certificate rotation started — interval: %v", rotationInterval)
}

// ─────────────────────────────────────────────────────────────────────────────
// rotate — internal: generates a new self-signed certificate
// ─────────────────────────────────────────────────────────────────────────────
// Everything happens in memory:
//   1. Generate RSA 2048 private key
//   2. Build X.509 certificate template (self-signed CA)
//   3. Sign the certificate with its own key
//   4. PEM-encode key and cert into byte slices (never written to disk)
//   5. Parse into tls.Certificate
//   6. Swap under write lock
// ─────────────────────────────────────────────────────────────────────────────

func (cm *CertManager) rotate() error {
	// ── Step 1: Generate RSA private key ───────────────────────────────
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("RSA key generation failed: %w", err)
	}

	// ── Step 2: Build X.509 certificate template ───────────────────────
	// Serial number must be unique per certificate. We use a random 128-bit
	// integer from crypto/rand.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial number generation failed: %w", err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Zero-Trust Hive"},
			CommonName:    "hive-gateway.local",
			Country:       []string{"US"},
			Province:      []string{"Cloud"},
			Locality:      []string{"Gateway"},
			StreetAddress: []string{},
		},

		// Validity window: now → now + certLifetime (2 hours).
		NotBefore: now,
		NotAfter:  now.Add(certLifetime),

		// Key usage: digital signatures + key encipherment (TLS server).
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// Self-signed → it is its own CA for this ephemeral context.
		BasicConstraintsValid: true,
		IsCA:                  true,

		// SANs: accept connections on any IP or localhost.
		IPAddresses: []net.IP{net.IPv4zero, net.IPv6zero, net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost", "hive-gateway.local", "*.hive.local"},
	}

	// ── Step 3: Self-sign the certificate ──────────────────────────────
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("certificate signing failed: %w", err)
	}

	// ── Step 4: PEM-encode in memory ───────────────────────────────────
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// ── Step 5: Parse into tls.Certificate ─────────────────────────────
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("TLS key pair creation failed: %w", err)
	}

	// ── Step 6: Swap under write lock ──────────────────────────────────
	cm.mu.Lock()
	cm.current = &tlsCert
	cm.generation++
	cm.mu.Unlock()

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Generation returns the current certificate generation number. Useful for
// health checks and monitoring endpoints.
// ─────────────────────────────────────────────────────────────────────────────

func (cm *CertManager) Generation() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.generation
}
