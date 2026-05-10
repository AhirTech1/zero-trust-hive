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
	"github.com/AhirTech1/zero-trust-hive/internal/adapters"
	"github.com/AhirTech1/zero-trust-hive/internal/auth"
	"github.com/AhirTech1/zero-trust-hive/internal/config"
)

const (
	backoffBase       = 1 * time.Second
	backoffMax        = 60 * time.Second
	backoffMultiplier = 2.0
	quicCloseCode     = 0
	quicCloseMessage  = "agent shutting down gracefully"
)

type exitReason int

const (
	exitShutdown   exitReason = iota
	exitDisconnect
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg := config.LoadFromEnv()

	gatewayAddr := flag.String("gateway", "127.0.0.1:443",
		"Gateway QUIC address (host:port)")
	agentID := flag.String("id", cfg.AgentID,
		"Unique agent identifier")
	flag.Parse()

	if envID := os.Getenv("HIVE_AGENT_ID"); envID != "" {
		*agentID = envID
	}

	printBanner(*agentID, *gatewayAddr, cfg)

	adapter := adapters.NewSystemAdapter(cfg.AdapterMode, cfg.AllowlistCommands)
	log.Printf("[AGENT] Adapter loaded: %s", adapter.Name())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	runAgent(*gatewayAddr, *agentID, adapter, sigChan, cfg)
}

func runAgent(gatewayAddr, agentID string, adapter adapters.EdgeAdapter,
	sigChan chan os.Signal, cfg *config.Config) {

	attempt := 0

	for {
		select {
		case sig := <-sigChan:
			log.Printf("[AGENT] Received %v — exiting cleanly", sig)
			os.Exit(0)
		default:
		}

		if attempt > 0 {
			delay := time.Duration(float64(backoffBase) * math.Pow(backoffMultiplier, float64(attempt-1)))
			if delay > backoffMax {
				delay = backoffMax
			}
			log.Printf("[AGENT] Reconnecting in %v (attempt %d)...", delay, attempt+1)
			time.Sleep(delay)
		}

		attempt++

		log.Printf("[AGENT] Dialing Gateway at %s (attempt %d)...", gatewayAddr, attempt)

		conn, err := dialGateway(gatewayAddr)
		if err != nil {
			log.Printf("[AGENT] Connection failed: %v", err)
			continue
		}

		log.Printf("[AGENT] Connected to Gateway at %s", gatewayAddr)

		if err := registerAgent(conn, agentID, cfg.AgentSecret); err != nil {
			log.Printf("[AGENT] Registration failed: %v", err)
			conn.CloseWithError(1, "registration failed")
			continue
		}

		log.Printf("[AGENT] Registered as %q", agentID)
		attempt = 0

		exitReason := commandLoop(conn, adapter, sigChan)

		switch exitReason {
		case exitShutdown:
			log.Println("[AGENT] Shutdown — sending CONNECTION_CLOSE frame")
			conn.CloseWithError(quic.ApplicationErrorCode(quicCloseCode), quicCloseMessage)
			time.Sleep(200 * time.Millisecond)
			log.Println("[AGENT] Clean shutdown complete — goodbye.")
			os.Exit(0)

		case exitDisconnect:
			log.Println("[AGENT] Connection lost — entering reconnection loop")
			continue
		}
	}
}

func dialGateway(addr string) (*quic.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"hive-quic"},
		MinVersion:         tls.VersionTLS13,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, &quic.Config{})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial to %s failed: %w", addr, err)
	}
	return conn, nil
}

func registerAgent(conn *quic.Conn, agentID, agentSecret string) error {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open registration stream: %w", err)
	}

	payload := agentID
	if agentSecret != "" {
		mac := auth.ComputeMAC(agentID, agentSecret)
		payload = agentID + "\n" + mac
	}

	if _, err := stream.Write([]byte(payload)); err != nil {
		stream.Close()
		return fmt.Errorf("failed to write agent ID: %w", err)
	}

	stream.Close()
	return nil
}

func commandLoop(conn *quic.Conn, adapter adapters.EdgeAdapter, sigChan chan os.Signal) exitReason {
	log.Println("[AGENT] Entering command loop — waiting for Gateway dispatches...")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	signalReceived := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			close(signalReceived)
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		streamPtr, err := conn.AcceptStream(ctx)
		if err != nil {
			select {
			case <-signalReceived:
				log.Println("[AGENT] Death Interceptor activated — draining in-flight commands...")
				wg.Wait()
				cancel()
				return exitShutdown
			default:
			}

			if conn.Context().Err() != nil {
				wg.Wait()
				cancel()
				return exitDisconnect
			}
			log.Printf("[AGENT] Failed to accept stream: %v", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleCommand(streamPtr, adapter)
		}()
	}
}

func handleCommand(stream *quic.Stream, adapter adapters.EdgeAdapter) {
	defer stream.Close()

	payload, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("[AGENT] Failed to read command: %v", err)
		stream.Write([]byte(fmt.Sprintf("error: failed to read command: %v", err)))
		return
	}

	if len(payload) == 0 {
		log.Printf("[AGENT] Received empty command — ignoring")
		stream.Write([]byte("error: empty command"))
		return
	}

	log.Printf("[AGENT] Received command: %q", string(payload))

	result, err := adapter.ExecuteIntent(payload)
	if err != nil {
		log.Printf("[AGENT] Execution failed: %v", err)
		stream.Write([]byte(fmt.Sprintf("error: %v", err)))
		return
	}

	if _, err := stream.Write(result); err != nil {
		log.Printf("[AGENT] Failed to write response: %v", err)
		return
	}

	log.Printf("[AGENT] Response sent (%d bytes)", len(result))
}

func printBanner(agentID, gatewayAddr string, cfg *config.Config) {
	fmt.Println(`
              --- EDGE AGENT v0.1.0 ---
         Zero-Trust Deployment Engine`)
	log.Printf("[AGENT] Agent ID:     %s", agentID)
	log.Printf("[AGENT] Gateway:      %s", gatewayAddr)
	log.Printf("[AGENT] Adapter:      %s mode", cfg.AdapterMode)
}