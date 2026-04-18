// ─────────────────────────────────────────────────────────────────────────────
// Package adapters — Universal Sidecar Adapter
// ─────────────────────────────────────────────────────────────────────────────
// The SidecarAdapter expects a JSON envelope over the QUIC tunnel.
// Envelope format:
//
//	{
//	  "routing": {"protocol": "http"|"tcp", "target": "127.0.0.1:8080"},
//	  "payload_format": "json"|"raw",
//	  "payload": "..."
//	}
//
// It unwraps the payload and forwards it to the local target, acting as a
// zero-trust sidecar proxy.
// ─────────────────────────────────────────────────────────────────────────────
package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// Envelope defines the expected incoming JSON structure.
type Envelope struct {
	Routing struct {
		Protocol string `json:"protocol"` // "http" or "tcp"
		Target   string `json:"target"`   // e.g., "127.0.0.1:8080"
	} `json:"routing"`
	PayloadFormat string `json:"payload_format"` // "json" or "raw"
	Payload       string `json:"payload"`
}

// SidecarAdapter acts as a local proxy forwarding Gateway payloads to local ports.
type SidecarAdapter struct {
	httpClient *http.Client
}

func NewSidecarAdapter() *SidecarAdapter {
	return &SidecarAdapter{
		// Optimize local HTTP client for fast localhost forwarding
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       100,
				IdleConnTimeout:    90 * time.Second,
				DisableCompression: true,
			},
		},
	}
}

func (s *SidecarAdapter) Name() string {
	return "SidecarAdapter"
}

func (s *SidecarAdapter) ExecuteIntent(raw []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		log.Printf("[SIDECAR] ✗ Failed to parse envelope: %v", err)
		return nil, fmt.Errorf("invalid sidecar envelope: %v", err)
	}

	target := env.Routing.Target
	if target == "" {
		return nil, fmt.Errorf("routing.target is required")
	}

	log.Printf("[SIDECAR] ▸ Forwarding via %s to %s", env.Routing.Protocol, target)

	switch env.Routing.Protocol {
	case "http":
		return s.forwardHTTP(target, env.PayloadFormat, env.Payload)
	case "tcp":
		return s.forwardTCP(target, env.Payload)
	default:
		return nil, fmt.Errorf("unsupported protocol: %q", env.Routing.Protocol)
	}
}

func (s *SidecarAdapter) forwardHTTP(target, format, payload string) ([]byte, error) {
	url := fmt.Sprintf("http://%s", target)

	// Create context to prevent hanging on bad connections
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %v", err)
	}

	if format == "json" {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "text/plain")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http proxy error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy response: %v", err)
	}

	log.Printf("[SIDECAR] ✓ HTTP Forward complete: %s (Status: %d, Bytes: %d)", target, resp.StatusCode, len(body))
	return body, nil
}

func (s *SidecarAdapter) forwardTCP(target, payload string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp proxy error: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		return nil, fmt.Errorf("failed to write to tcp target: %v", err)
	}

	// For TCP, we read until EOF or timeout. Some raw TCP servers close after response.
	body, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		// Log but return what we got
		log.Printf("[SIDECAR] ⚠ TCP read ended with error: %v", err)
	}

	log.Printf("[SIDECAR] ✓ TCP Forward complete: %s (Bytes: %d)", target, len(body))
	return body, nil
}
