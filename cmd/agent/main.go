// ─────────────────────────────────────────────────────────────────────────────
// Zero-Trust Hive — Edge Agent Entry Point
// ─────────────────────────────────────────────────────────────────────────────
// The Edge Agent is the lightweight binary that runs on target machines. It
// dials out to the Cloud Gateway over QUIC, registers itself, and then
// listens for commands dispatched via the Gateway's Control API.
//
// Architecture:
//
//	┌─────────────┐          QUIC/TLS 1.3          ┌─────────────────┐
//	│  Edge Agent  │──────── (UDP :443) ──────────▶│  Cloud Gateway  │
//	│              │◀─── command streams ──────────│                 │
//	│  Adapter →   │──── response streams ────────▶│  Control API    │
//	└─────────────┘                                └─────────────────┘
//
// Key Behaviors:
//  1. QUIC Anchor — dials out to the Gateway using InsecureSkipVerify
//     (because the Gateway uses ephemeral in-memory certificates)
//  2. Exponential Backoff — if the connection drops, the agent retries
//     with increasing delays (1s → 2s → 4s → 8s → ... → 60s max)
//  3. Death Interceptor — catches SIGINT/SIGTERM and sends a clean
//     CONNECTION_CLOSE frame before exiting, so the Gateway scrubs
//     the zombie socket immediately
//  4. Universal Adapter — all command execution flows through the
//     EdgeAdapter interface (no hardcoded switch statements)
//
// ─────────────────────────────────────────────────────────────────────────────
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/zero-trust-hive/cli/internal/adapters"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const (
	// defaultGatewayAddr — the default Gateway address to dial.
	// Overridable via the -gateway flag.
	defaultGatewayAddr = "127.0.0.1:443"

	// defaultAgentID — the default agent identifier.
	// Overridable via the -id flag or HIVE_AGENT_ID env var.
	defaultAgentID = "agent-001"

	// backoffBase — initial retry delay for exponential backoff.
	backoffBase = 1 * time.Second

	// backoffMax — maximum retry delay cap.
	backoffMax = 60 * time.Second

	// backoffMultiplier — exponential growth factor per retry.
	backoffMultiplier = 2.0

	// quicCloseCode — the application error code sent in CONNECTION_CLOSE
	// frames during graceful shutdown.
	quicCloseCode = 0

	// quicCloseMessage — the human-readable reason in CONNECTION_CLOSE.
	quicCloseMessage = "agent shutting down gracefully"
)

// ─────────────────────────────────────────────────────────────────────────────
// main — orchestrates the agent lifecycle
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	// ── Parse CLI flags ────────────────────────────────────────────────
	gatewayAddr := flag.String("gateway", defaultGatewayAddr,
		"Gateway address to connect to (host:port)")
	agentID := flag.String("id", defaultAgentID,
		"Unique agent identifier (used for registration)")
	flag.Parse()

	// Allow env var override for agent ID (useful in containers/CI).
	if envID := os.Getenv("HIVE_AGENT_ID"); envID != "" {
		*agentID = envID
	}

	printBanner(*agentID, *gatewayAddr)

	// ── Initialize the adapter ─────────────────────────────────────────
	// The SystemAdapter is the default. In future phases, this could be
	// selected based on CLI flags or config files.
	adapter := adapters.NewSystemAdapter()
	log.Printf("[AGENT] Adapter loaded: %s", adapter.Name())

	// ── Set up the Death Interceptor ───────────────────────────────────
	// Catch SIGINT (Ctrl+C) and SIGTERM so we can send a clean
	// CONNECTION_CLOSE frame before exiting.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// ── Enter the reconnection loop ────────────────────────────────────
	// This outer loop handles connection loss. If the connection drops
	// (network failure, gateway restart), the agent retries with
	// exponential backoff until it reconnects.
	runAgent(*gatewayAddr, *agentID, adapter, sigChan)
}

// ─────────────────────────────────────────────────────────────────────────────
// runAgent — the main reconnection loop with exponential backoff
// ─────────────────────────────────────────────────────────────────────────────
// This function never returns under normal operation. It loops forever,
// connecting to the Gateway, running the command loop, and reconnecting
// on failure. The only exit path is through the Death Interceptor (signal).
// ─────────────────────────────────────────────────────────────────────────────

func runAgent(gatewayAddr, agentID string, adapter adapters.EdgeAdapter, sigChan chan os.Signal) {
	attempt := 0

	for {
		// Check if a shutdown signal was received while we were backing off.
		select {
		case sig := <-sigChan:
			log.Printf("[AGENT] Received %v during reconnection — exiting cleanly", sig)
			os.Exit(0)
		default:
			// No signal — proceed with connection attempt.
		}

		// ── Calculate backoff delay ────────────────────────────────────
		// First attempt has zero delay. Subsequent attempts use exponential
		// backoff capped at backoffMax.
		if attempt > 0 {
			delay := time.Duration(float64(backoffBase) * math.Pow(backoffMultiplier, float64(attempt-1)))
			if delay > backoffMax {
				delay = backoffMax
			}
			log.Printf("[AGENT] ⏳ Reconnecting in %v (attempt %d)...", delay, attempt+1)
			time.Sleep(delay)
		}

		attempt++

		// ── Dial the Gateway ───────────────────────────────────────────
		log.Printf("[AGENT] Dialing Gateway at %s (attempt %d)...", gatewayAddr, attempt)

		conn, err := dialGateway(gatewayAddr)
		if err != nil {
			log.Printf("[AGENT] ✗ Connection failed: %v", err)
			continue // → backoff and retry
		}

		log.Printf("[AGENT] ✓ Connected to Gateway at %s", gatewayAddr)

		// ── Register with the Gateway ──────────────────────────────────
		// Send our agent ID on the first stream so the Gateway can register
		// us in its routing table.
		if err := registerAgent(conn, agentID); err != nil {
			log.Printf("[AGENT] ✗ Registration failed: %v", err)
			conn.CloseWithError(1, "registration failed")
			continue
		}

		log.Printf("[AGENT] ✓ Registered as %q", agentID)

		// ── Reset backoff on successful connection ─────────────────────
		attempt = 0

		// ── Enter the command loop ─────────────────────────────────────
		// This blocks until the connection drops or a shutdown signal is
		// received. Returns the reason the loop exited.
		exitReason := commandLoop(conn, adapter, sigChan)

		switch exitReason {
		case exitShutdown:
			// Death Interceptor fired — send CONNECTION_CLOSE and exit.
			log.Println("[AGENT] 🛑 Shutdown signal received — sending CONNECTION_CLOSE frame")
			conn.CloseWithError(quic.ApplicationErrorCode(quicCloseCode), quicCloseMessage)

			// Brief pause to let the frame flush before os.Exit.
			time.Sleep(200 * time.Millisecond)

			log.Println("[AGENT] ✓ Clean shutdown complete — goodbye.")
			os.Exit(0)

		case exitDisconnect:
			// Connection dropped — loop back to reconnect.
			log.Println("[AGENT] ⚡ Connection lost — entering reconnection loop")
			continue
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Exit reasons for the command loop
// ─────────────────────────────────────────────────────────────────────────────

type exitReason int

const (
	exitShutdown   exitReason = iota // Graceful shutdown (SIGINT/SIGTERM)
	exitDisconnect                   // Connection dropped (network failure)
)

// ─────────────────────────────────────────────────────────────────────────────
// dialGateway — establishes a QUIC connection to the Cloud Gateway
// ─────────────────────────────────────────────────────────────────────────────
// Uses InsecureSkipVerify because the Gateway generates ephemeral self-signed
// certificates in memory. In a production deployment, you would pin the
// Gateway's CA certificate or use a mutual TLS scheme.
// ─────────────────────────────────────────────────────────────────────────────

func dialGateway(addr string) (*quic.Conn, error) {
	tlsConfig := &tls.Config{
		// InsecureSkipVerify is required because the Gateway uses ephemeral
		// self-signed certificates generated at boot. There is no CA chain
		// to verify against. In production, this would be replaced with
		// certificate pinning or a proper PKI.
		InsecureSkipVerify: true,

		// Must match the Gateway's ALPN protocol list.
		NextProtos: []string{"hive-quic"},

		// Enforce TLS 1.3 minimum to match the Gateway.
		MinVersion: tls.VersionTLS13,
	}

	// Dial the Gateway with a 10-second timeout for the handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial to %s failed: %w", addr, err)
	}

	return conn, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// registerAgent — sends the agent ID to the Gateway on the first stream
// ─────────────────────────────────────────────────────────────────────────────
// This follows the Gateway's identification protocol:
//   1. Open a bidirectional stream
//   2. Write the agent ID as UTF-8 bytes
//   3. Close the stream to signal "ID sent"
// ─────────────────────────────────────────────────────────────────────────────

func registerAgent(conn *quic.Conn, agentID string) error {
	// Open a stream for sending our agent ID.
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open registration stream: %w", err)
	}

	// Write the agent ID.
	if _, err := stream.Write([]byte(agentID)); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write agent ID: %w", err)
	}

	// Close the stream to signal that the ID has been fully sent.
	// The Gateway reads until EOF to capture the full ID.
	stream.Close()

	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// commandLoop — listens for and executes commands from the Gateway
// ─────────────────────────────────────────────────────────────────────────────
// This function blocks, accepting incoming QUIC streams from the Gateway.
// Each stream carries a single command. The command is executed via the
// adapter and the result is written back to the stream.
//
// The loop exits when:
//   - A shutdown signal is received (returns exitShutdown)
//   - The connection is lost (returns exitDisconnect)
// ─────────────────────────────────────────────────────────────────────────────

func commandLoop(conn *quic.Conn, adapter adapters.EdgeAdapter, sigChan chan os.Signal) exitReason {
	log.Println("[AGENT] ▸ Entering command loop — waiting for Gateway dispatches...")

	var wg sync.WaitGroup

	// Create a cancellable context so we can interrupt AcceptStream
	// when a shutdown signal arrives.
	ctx, cancel := context.WithCancel(context.Background())

	// Monitor the signal channel in a dedicated goroutine.
	// When a signal arrives, cancel the context so AcceptStream unblocks.
	signalReceived := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			close(signalReceived)
			cancel()
		case <-ctx.Done():
			// Context cancelled for other reasons (e.g., disconnect).
		}
	}()

	for {
		// Accept the next command stream. This blocks until:
		//   - The Gateway opens a stream (a command arrives)
		//   - The context is cancelled (shutdown signal)
		//   - The connection drops
		streamPtr, err := conn.AcceptStream(ctx)
		if err != nil {
			// Determine if the error was caused by our shutdown signal.
			select {
			case <-signalReceived:
				log.Println("[AGENT] Death Interceptor activated — draining in-flight commands...")
				wg.Wait()
				cancel()
				return exitShutdown
			default:
			}

			// Not a signal — check if the connection died.
			if conn.Context().Err() != nil {
				wg.Wait()
				cancel()
				return exitDisconnect
			}
			log.Printf("[AGENT] ⚠ Failed to accept stream: %v", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleCommand(streamPtr, adapter)
		}()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// handleCommand — processes a single command stream
// ─────────────────────────────────────────────────────────────────────────────
// Reads the command payload from the stream, executes it via the adapter,
// and writes the result back to the stream.
// ─────────────────────────────────────────────────────────────────────────────

func handleCommand(stream *quic.Stream, adapter adapters.EdgeAdapter) {
	defer stream.Close()

	// ── Read the command payload ───────────────────────────────────────
	// The Gateway writes the command and then closes its write side
	// (CancelWrite), so we read until EOF.
	payload, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("[AGENT] ⚠ Failed to read command: %v", err)
		stream.Write([]byte(fmt.Sprintf("error: failed to read command: %v", err)))
		return
	}

	if len(payload) == 0 {
		log.Printf("[AGENT] ⚠ Received empty command — ignoring")
		stream.Write([]byte("error: empty command"))
		return
	}

	log.Printf("[AGENT] ▸ Received command: %q", string(payload))

	// ── Execute via the adapter ────────────────────────────────────────
	// The adapter handles allowlisting, timeout enforcement, and
	// execution. We just forward the payload and return the result.
	result, err := adapter.ExecuteIntent(payload)
	if err != nil {
		log.Printf("[AGENT] ✗ Execution failed: %v", err)
		stream.Write([]byte(fmt.Sprintf("error: %v", err)))
		return
	}

	// ── Write the result back ──────────────────────────────────────────
	if _, err := stream.Write(result); err != nil {
		log.Printf("[AGENT] ⚠ Failed to write response: %v", err)
		return
	}

	log.Printf("[AGENT] ✓ Response sent (%d bytes)", len(result))
}

// ─────────────────────────────────────────────────────────────────────────────
// printBanner — agent startup banner
// ─────────────────────────────────────────────────────────────────────────────

func printBanner(agentID, gatewayAddr string) {
	banner := `
═══════════════════════════════════════════════════════════════
              ██╗  ██╗██╗██╗   ██╗███████╗
              ██║  ██║██║██║   ██║██╔════╝
              ███████║██║██║   ██║█████╗
              ██╔══██║██║╚██╗ ██╔╝██╔══╝
              ██║  ██║██║ ╚████╔╝ ███████╗
              ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝

               ── EDGE AGENT v0.1.0 ──
           Zero-Trust Deployment Engine
═══════════════════════════════════════════════════════════════`

	fmt.Println(banner)
	log.Printf("[AGENT] Agent ID:     %s", agentID)
	log.Printf("[AGENT] Gateway:      %s", gatewayAddr)
	log.Printf("[AGENT] Adapter:      SystemAdapter")
	log.Println("═══════════════════════════════════════════════════════")
}
