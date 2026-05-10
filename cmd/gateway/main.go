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

	"github.com/AhirTech1/zero-trust-hive/internal/audit"
	"github.com/AhirTech1/zero-trust-hive/internal/auth"
	"github.com/AhirTech1/zero-trust-hive/internal/config"
	"github.com/AhirTech1/zero-trust-hive/internal/network"
	"github.com/AhirTech1/zero-trust-hive/internal/ratelimit"
)

const shutdownTimeout = 10 * time.Second

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg := config.LoadFromEnv()

	printBanner()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Certificate manager.
	log.Println("--- Phase 1: Ephemeral Certificate Manager ---")
	certManager, err := auth.NewCertManager()
	if err != nil {
		log.Fatalf("[FATAL] Certificate manager: %v", err)
	}
	certManager.StartRotation(ctx)
	tlsConfig := certManager.GetTLSConfig()
	log.Printf("[BOOT] TLS 1.3 certificate ready (generation %d)", certManager.Generation())

	// Routing table.
	log.Println("--- Phase 2: Agent Routing Table ---")
	router := network.NewRouter()
	log.Printf("[BOOT] Routing table initialized")

	// Agent authentication.
	agentAuth := auth.NewAgentAuth(cfg.AgentSecret)
	if agentAuth.Enabled() {
		log.Printf("[BOOT] Agent authentication enabled (HMAC-SHA256)")
	} else {
		log.Printf("[BOOT] Agent authentication disabled (no HIVE_AGENT_SECRET set)")
	}

	// QUIC listener.
	log.Println("--- Phase 3: QUIC Ghost Endpoint ---")
	if err := network.StartQUICListener(ctx, tlsConfig, router, agentAuth); err != nil {
		log.Fatalf("[FATAL] QUIC listener: %v", err)
	}

	// JWT secret.
	jwtSecret := cfg.JWTSecret
	if jwtSecret == "" {
		jwtSecret = generateBearerToken()
		log.Println("[BOOT] HIVE_JWT_SECRET not set — generated ephemeral secret")
		log.Printf("  JWT SECRET: %s", jwtSecret)
	} else {
		log.Println("[BOOT] Using JWT secret from HIVE_JWT_SECRET")
	}

	bootstrapToken, _ := auth.GenerateToken(jwtSecret, "hive-admin", "admin")
	log.Printf("  BOOTSTRAP JWT (valid 24h): %s", bootstrapToken)

	// Firewall.
	firewall := network.NewSemanticFirewall()

	// Audit logger.
	auditLogger := audit.New(cfg.AuditLog)

	// Rate limiter.
	var rl *ratelimit.Limiter
	if cfg.RateLimit > 0 {
		rl = ratelimit.New(cfg.RateLimit)
		defer rl.Stop()
		log.Printf("[BOOT] Rate limiter: %d req/min per subject", cfg.RateLimit)
	}

	// Control API.
	controlAPI := network.NewControlAPI(router, jwtSecret, firewall, auditLogger, rl,
		cfg.APIListenAddr, cfg.CommandTimeout)

	go func() {
		if err := controlAPI.Start(); err != nil {
			log.Fatalf("[FATAL] Control API: %v", err)
		}
	}()

	log.Println("--- ZERO-TRUST HIVE GATEWAY READY ---")
	log.Printf("  QUIC Endpoint ........ %s (UDP)", cfg.QUICListenAddr)
	log.Printf("  HTTP Control API ..... %s (TCP)", cfg.APIListenAddr)
	log.Printf("  Certificate Rotation . Every 1 hour")
	log.Printf("  Semantic Firewall .... Active (%d rules)", firewall.Stats().RuleCount)
	log.Printf("  JWT Authentication ... Active (HMAC-SHA256)")
	if agentAuth.Enabled() {
		log.Printf("  Agent Authentication . Active (HMAC-SHA256)")
	}
	if auditLogger.Enabled() {
		log.Printf("  Audit Logging ........ Enabled")
	}
	log.Println("  Press Ctrl+C for graceful shutdown")

	<-ctx.Done()

	log.Println("--- SHUTDOWN INITIATED ---")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if err := controlAPI.Shutdown(shutdownCtx); err != nil {
		log.Printf("[SHUTDOWN] Control API error: %v", err)
	} else {
		log.Println("[SHUTDOWN] Control API stopped")
	}

	log.Printf("[SHUTDOWN] Agents connected: %d, Cert rotations: %d", router.Count(), certManager.Generation())
	log.Println("--- SHUTDOWN COMPLETE ---")
}

func generateBearerToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("[FATAL] Failed to generate token: %v", err)
	}
	return hex.EncodeToString(bytes)
}

func printBanner() {
	fmt.Println(`
  ______  ______  ______  ______       ______  ______  __  __  ______  ______
 /\___  \/\  ___\/\  == \/\  __ \     /\__  _\/\  == \/\ \/\ \/\  ___\/\__  _\
 \/_/  /__\ \  __\\ \  __<\ \ \/\ \    \/_/\ \/\ \  __<\ \ \_\ \ \___  \/_/\ \/
   /\_____\\ \_____\ \_\ \_\ \_____\      \ \_\\ \_\ \_\ \_____\/\_____\  \ \_\
   \/_____/ \/_____/\/_/ /_/\/_____/       \/_/ \/_/ /_/\/_____/\/_____/   \/_/

              --- CLOUD GATEWAY v0.1.0 ---
         Secure AI Agent Execution Tunnel`)
	fmt.Println()
}