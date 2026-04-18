// ─────────────────────────────────────────────────────────────────────────────
// Zero-Trust Hive — Cloud Gateway Entry Point
// ─────────────────────────────────────────────────────────────────────────────
// The Gateway is the central nervous system of the Zero-Trust Hive. It runs
// two concurrent services:
//
//  1. QUIC Ghost Endpoint (UDP :443)
//     Accepts mTLS-authenticated QUIC connections from Edge Agents. Each
//     agent is registered in a thread-safe routing table with a zero-zombie
//     watchdog that scrubs disconnected agents in real time.
//
//  2. HTTP Control API (TCP :8080)
//     Exposes POST /execute for operators to dispatch commands to agents.
//     Every request passes through three security layers: Bearer token
//     authentication, semantic firewall inspection, and a 5-second timeout.
//
// Certificates are generated entirely in memory (RSA 2048, TLS 1.3) and
// rotated every hour by a background ticker. No key material touches disk.
//
// Startup Sequence:
//  1. Generate ephemeral mTLS certificate → start rotation ticker
//  2. Create agent routing table
//  3. Start QUIC listener (background goroutine)
//  4. Start HTTP control API (background goroutine)
//  5. Block on OS signal (SIGINT/SIGTERM) for graceful shutdown
//
// ─────────────────────────────────────────────────────────────────────────────
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zero-trust-hive/cli/internal/auth"
	"github.com/zero-trust-hive/cli/internal/network"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────
// In production, these would come from environment variables or a secrets
// manager. For Phase 2, we generate a random token at boot and print it.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// shutdownTimeout — how long to wait for in-flight requests to finish
	// during graceful shutdown.
	shutdownTimeout = 10 * time.Second
)

// ─────────────────────────────────────────────────────────────────────────────
// main — orchestrates the gateway startup and shutdown
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	printBanner()

	// ── Master context: cancelled on OS signal ─────────────────────────
	// All subsystems (cert rotation, QUIC listener, API) derive from this
	// context. When we receive SIGINT/SIGTERM, everything shuts down.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// =====================================================================
	// PHASE 1: Ephemeral mTLS Certificate Manager
	// =====================================================================
	// Generate the initial in-memory certificate and start the hourly
	// rotation ticker. If initial generation fails, the gateway cannot
	// start — exit immediately.

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  PHASE 1: Initializing Ephemeral Certificate Manager")
	log.Println("═══════════════════════════════════════════════════════")

	certManager, err := auth.NewCertManager()
	if err != nil {
		log.Fatalf("[FATAL] Certificate manager initialization failed: %v", err)
	}

	// Start the 1-hour rotation background loop.
	certManager.StartRotation(ctx)

	// Build the TLS config that QUIC will use for all handshakes.
	tlsConfig := certManager.GetTLSConfig()

	log.Printf("[BOOT] ✓ TLS 1.3 certificate ready (generation %d)", certManager.Generation())

	// =====================================================================
	// PHASE 2: Agent Routing Table
	// =====================================================================
	// The router is the single source of truth for active agent connections.
	// It's shared between the QUIC listener (writes) and the HTTP API (reads).

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  PHASE 2: Initializing Agent Routing Table")
	log.Println("═══════════════════════════════════════════════════════")

	router := network.NewRouter()
	log.Printf("[BOOT] ✓ Routing table initialized (zero-zombie guarantee active)")

	// =====================================================================
	// PHASE 3: QUIC Ghost Endpoint (UDP :443)
	// =====================================================================
	// Start the QUIC listener in a background goroutine. It will accept
	// agent connections and register them in the routing table.

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  PHASE 3: Starting QUIC Ghost Endpoint")
	log.Println("═══════════════════════════════════════════════════════")

	if err := network.StartQUICListener(ctx, tlsConfig, router); err != nil {
		log.Fatalf("[FATAL] QUIC listener failed to start: %v", err)
	}

	// =====================================================================
	// PHASE 4: HTTP Control API (TCP :8080)
	// =====================================================================
	// Generate a bearer token for this session and start the API server.
	// The token is printed to stdout so the operator can use it.

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  PHASE 4: Starting HTTP Control API")
	log.Println("═══════════════════════════════════════════════════════")

	// Generate a cryptographically random bearer token for this session.
	// In production, this would come from a secrets manager or env var.
	bearerToken := generateBearerToken()

	// Check if a token was provided via environment variable.
	if envToken := os.Getenv("HIVE_API_TOKEN"); envToken != "" {
		bearerToken = envToken
		log.Println("[BOOT] Using bearer token from HIVE_API_TOKEN environment variable")
	} else {
		log.Println("═══════════════════════════════════════════════════════")
		log.Printf("  BEARER TOKEN: %s", bearerToken)
		log.Println("  (Save this token — it is required for API access)")
		log.Println("═══════════════════════════════════════════════════════")
	}

	controlAPI := network.NewControlAPI(router, bearerToken)

	// Start the API server in a background goroutine.
	go func() {
		if err := controlAPI.Start(); err != nil {
			log.Fatalf("[FATAL] Control API failed: %v", err)
		}
	}()

	// =====================================================================
	// READY — All systems operational
	// =====================================================================

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  ✓ ZERO-TRUST HIVE GATEWAY — ALL SYSTEMS OPERATIONAL")
	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  Services:")
	log.Println("    • QUIC Ghost Endpoint .... UDP 0.0.0.0:443")
	log.Println("    • HTTP Control API ....... TCP 0.0.0.0:8080")
	log.Println("    • Certificate Rotation ... Every 1 hour")
	log.Println("    • Semantic Firewall ...... Active")
	log.Println("    • Zero-Zombie Watchdog ... Active")
	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  Press Ctrl+C to initiate graceful shutdown")

	// =====================================================================
	// BLOCK — Wait for shutdown signal
	// =====================================================================
	// The main goroutine blocks here until SIGINT or SIGTERM is received.
	// When the signal fires, the context is cancelled and all subsystems
	// begin their shutdown procedures.

	<-ctx.Done()

	log.Println("")
	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  SHUTDOWN INITIATED — draining connections...")
	log.Println("═══════════════════════════════════════════════════════")

	// ── Graceful shutdown with timeout ──────────────────────────────────
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Shut down the HTTP API first (stop accepting new commands).
	if err := controlAPI.Shutdown(shutdownCtx); err != nil {
		log.Printf("[SHUTDOWN] ⚠ Control API shutdown error: %v", err)
	} else {
		log.Println("[SHUTDOWN] ✓ Control API stopped")
	}

	// The QUIC listener shuts down via context cancellation (already done).
	log.Println("[SHUTDOWN] ✓ QUIC listener stopped")

	// Report final statistics.
	log.Printf("[SHUTDOWN] Final state: %d agents were connected", router.Count())
	log.Printf("[SHUTDOWN] Certificate rotations: %d generations", certManager.Generation())

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  ✓ ZERO-TRUST HIVE GATEWAY — SHUTDOWN COMPLETE")
	log.Println("═══════════════════════════════════════════════════════")
}

// ─────────────────────────────────────────────────────────────────────────────
// generateBearerToken — creates a cryptographically random 32-byte hex token
// ─────────────────────────────────────────────────────────────────────────────
// Used when no HIVE_API_TOKEN environment variable is set. The token is
// printed to stdout during boot so the operator can save it.
// ─────────────────────────────────────────────────────────────────────────────

func generateBearerToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// If we can't generate random bytes, the system's entropy pool is
		// exhausted — this is a critical security failure.
		log.Fatalf("[FATAL] Failed to generate bearer token: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// printBanner — gateway startup banner
// ─────────────────────────────────────────────────────────────────────────────

func printBanner() {
	banner := `
═══════════════════════════════════════════════════════════════
  ______  ______  ______  ______       ______  ______  __  __  ______  ______
 /\___  \/\  ___\/\  == \/\  __ \     /\__  _\/\  == \/\ \/\ \/\  ___\/\__  _\
 \/_/  /__\ \  __\\ \  __<\ \ \/\ \    \/_/\ \/\ \  __<\ \ \_\ \ \___  \/_/\ \/
   /\_____\\ \_____\ \_\ \_\ \_____\      \ \_\\ \_\ \_\ \_____\/\_____\  \ \_\
   \/_____/ \/_____/\/_/ /_/\/_____/       \/_/ \/_/ /_/\/_____/\/_____/   \/_/

              ██╗  ██╗██╗██╗   ██╗███████╗
              ██║  ██║██║██║   ██║██╔════╝
              ███████║██║██║   ██║█████╗
              ██╔══██║██║╚██╗ ██╔╝██╔══╝
              ██║  ██║██║ ╚████╔╝ ███████╗
              ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝

             ── CLOUD GATEWAY v0.1.0 ──
           Zero-Trust Deployment Engine
═══════════════════════════════════════════════════════════════`

	fmt.Println(banner)
}
