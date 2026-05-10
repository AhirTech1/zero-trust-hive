package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/AhirTech1/zero-trust-hive/internal/auth"
)

const maxAgentIDLen = 256

// StartQUICListener binds a UDP socket and enters the QUIC accept loop.
func StartQUICListener(ctx context.Context, tlsConfig *tls.Config, router *Router, agentAuth *auth.AgentAuth) error {
	udpAddr, err := net.ResolveUDPAddr("udp", tlsConfig.ServerName)
	if err != nil {
		// ServerName may be empty for 0.0.0.0 listeners.
		udpAddr, err = net.ResolveUDPAddr("udp", "0.0.0.0:443")
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address: %w", err)
		}
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", udpAddr, err)
	}

	transport := &quic.Transport{Conn: udpConn}

	listener, err := transport.Listen(tlsConfig, &quic.Config{
		MaxIdleTimeout: 0,
	})
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	log.Printf("[QUIC] Ghost Endpoint listening on %s (UDP/QUIC)", udpAddr)

	go func() {
		defer listener.Close()
		defer udpConn.Close()
		defer transport.Close()

		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					log.Printf("[QUIC] Listener shutting down (context cancelled)")
					return
				}
				log.Printf("[QUIC] Accept error: %v", err)
				continue
			}
			go handleAgentConnection(ctx, conn, router, agentAuth)
		}
	}()

	return nil
}

// handleAgentConnection processes a newly accepted QUIC connection.
func handleAgentConnection(ctx context.Context, conn *quic.Conn, router *Router, agentAuth *auth.AgentAuth) {
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[QUIC] New connection from %s", remoteAddr)

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("[QUIC] Failed to accept ID stream from %s: %v", remoteAddr, err)
		conn.CloseWithError(1, "failed to accept identification stream")
		return
	}

	idBytes, err := io.ReadAll(io.LimitReader(stream, maxAgentIDLen))
	if err != nil {
		log.Printf("[QUIC] Failed to read agent ID from %s: %v", remoteAddr, err)
		conn.CloseWithError(2, "failed to read agent identification")
		return
	}
	stream.Close()

	rawPayload := string(idBytes)
	if rawPayload == "" {
		log.Printf("[QUIC] Empty agent ID from %s — rejecting", remoteAddr)
		conn.CloseWithError(3, "empty agent ID")
		return
	}

	// Validate agent identity if agent authentication is enabled.
	agentID, err := agentAuth.ValidateAgentID(rawPayload)
	if err != nil {
		log.Printf("[QUIC] Agent authentication failed from %s: %v", remoteAddr, err)
		conn.CloseWithError(4, fmt.Sprintf("agent authentication failed: %v", err))
		return
	}

	router.Register(agentID, conn)
	log.Printf("[QUIC] Agent %q authenticated from %s", agentID, remoteAddr)
}