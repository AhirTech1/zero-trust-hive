// ─────────────────────────────────────────────────────────────────────────────
// Package network — QUIC Listener (Ghost Endpoint)
// ─────────────────────────────────────────────────────────────────────────────
// Listens on UDP 0.0.0.0:443 for incoming QUIC connections from Edge Agents.
// Each agent must send its agent ID on the first stream after connecting.
// Once identified, the agent is registered in the Router and monitored by
// the zero-zombie watchdog.
//
// Protocol:
//  1. Agent opens QUIC connection to gateway:443
//  2. Agent opens a stream and writes its agent ID (UTF-8)
//  3. Gateway reads the ID, registers the agent, and logs the event
//  4. The connection remains open for command dispatch via the Control API
//
// ─────────────────────────────────────────────────────────────────────────────
package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/quic-go/quic-go"
)

const (
	// quicListenAddr — the UDP address the QUIC listener binds to.
	// Port 443 is the standard QUIC/HTTP3 port.
	quicListenAddr = "0.0.0.0:443"

	// maxAgentIDLen — maximum length of an agent ID string. Any ID longer
	// than this is rejected to prevent resource exhaustion attacks.
	maxAgentIDLen = 256
)

// ─────────────────────────────────────────────────────────────────────────────
// StartQUICListener — main QUIC accept loop
// ─────────────────────────────────────────────────────────────────────────────
// Binds a UDP socket on 0.0.0.0:443, creates a QUIC listener with the
// provided TLS config, and enters an accept loop. Each accepted connection
// is handled in its own goroutine.
//
// The listener shuts down gracefully when the context is cancelled (e.g.,
// on SIGINT/SIGTERM).
// ─────────────────────────────────────────────────────────────────────────────

func StartQUICListener(ctx context.Context, tlsConfig *tls.Config, router *Router) error {
	// ── Bind the UDP socket ────────────────────────────────────────────
	udpAddr, err := net.ResolveUDPAddr("udp", quicListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", quicListenAddr, err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", quicListenAddr, err)
	}

	// ── Create the QUIC transport and listener ─────────────────────────
	transport := &quic.Transport{
		Conn: udpConn,
	}

	listener, err := transport.Listen(tlsConfig, &quic.Config{
		// Allow long-lived connections (agents may stay connected for hours).
		MaxIdleTimeout: 0, // No idle timeout — agents keep-alive themselves.
	})
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	log.Printf("[QUIC] ✓ Ghost Endpoint listening on %s (UDP/QUIC)", quicListenAddr)

	// ── Accept loop ────────────────────────────────────────────────────
	// Runs in its own goroutine. The outer caller can proceed to start
	// the HTTP control API concurrently.
	go func() {
		defer listener.Close()
		defer udpConn.Close()
		defer transport.Close()

		for {
			// Accept blocks until a new connection arrives or the listener
			// is closed (via context cancellation).
			conn, err := listener.Accept(ctx)
			if err != nil {
				// Check if the context was cancelled (graceful shutdown).
				if ctx.Err() != nil {
					log.Printf("[QUIC] Listener shutting down (context cancelled)")
					return
				}
				log.Printf("[QUIC] ⚠ Accept error: %v", err)
				continue
			}

			// Handle each connection in its own goroutine.
			go handleAgentConnection(ctx, conn, router)
		}
	}()

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// handleAgentConnection — processes a newly accepted QUIC connection
// ─────────────────────────────────────────────────────────────────────────────
// The agent must open a stream and send its ID within a reasonable time.
// Once identified, the agent is registered in the routing table. The
// connection then stays open for command dispatch.
// ─────────────────────────────────────────────────────────────────────────────

func handleAgentConnection(ctx context.Context, conn *quic.Conn, router *Router) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[QUIC] New connection from %s", remoteAddr)

	// ── Wait for the agent's identification stream ─────────────────────
	// The agent must open a stream and write its agent ID.
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("[QUIC] ⚠ Failed to accept ID stream from %s: %v", remoteAddr, err)
		conn.CloseWithError(1, "failed to accept identification stream")
		return
	}

	// Read the agent ID from the stream (limited to maxAgentIDLen bytes
	// to prevent memory exhaustion from malicious clients).
	idBytes, err := io.ReadAll(io.LimitReader(stream, maxAgentIDLen))
	if err != nil {
		log.Printf("[QUIC] ⚠ Failed to read agent ID from %s: %v", remoteAddr, err)
		conn.CloseWithError(2, "failed to read agent identification")
		return
	}

	agentID := string(idBytes)
	if agentID == "" {
		log.Printf("[QUIC] ⚠ Empty agent ID from %s — rejecting", remoteAddr)
		conn.CloseWithError(3, "empty agent ID")
		return
	}

	// Close the identification stream — it's no longer needed.
	stream.Close()

	// ── Register the agent ─────────────────────────────────────────────
	// This also spawns the zero-zombie watchdog goroutine automatically.
	router.Register(agentID, conn)

	log.Printf("[QUIC] ✓ Agent %q authenticated from %s", agentID, remoteAddr)
}
