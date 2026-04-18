// ─────────────────────────────────────────────────────────────────────────────
// Package network — Thread-Safe Agent Routing Table
// ─────────────────────────────────────────────────────────────────────────────
// The Router maintains a global map of agentID → agentConnection for all
// active Edge Agents. It tracks connection uptime and guarantees zero-zombies.
// ─────────────────────────────────────────────────────────────────────────────
package network

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// AgentInfo represents public details about an agent, returned by the API.
type AgentInfo struct {
	AgentID     string    `json:"agent_id"`
	Uptime      string    `json:"uptime"`
	ConnectedAt time.Time `json:"connected_at"`
}

// agentConnection tracks internal connection state.
type agentConnection struct {
	conn        *quic.Conn
	connectedAt time.Time
}

type Router struct {
	mu     sync.RWMutex
	agents map[string]agentConnection
}

func NewRouter() *Router {
	return &Router{
		agents: make(map[string]agentConnection),
	}
}

func (r *Router) Register(agentID string, conn *quic.Conn) {
	r.mu.Lock()
	if old, exists := r.agents[agentID]; exists {
		log.Printf("[ROUTER] Agent %q re-registered — replacing connection from %s", agentID, old.conn.RemoteAddr())
	}
	r.agents[agentID] = agentConnection{
		conn:        conn,
		connectedAt: time.Now(),
	}
	r.mu.Unlock()

	log.Printf("[ROUTER] ✓ Agent registered: %q from %s (total: %d)", agentID, conn.RemoteAddr(), r.Count())
	go r.watchConnection(agentID, conn)
}

func (r *Router) Deregister(agentID string) {
	r.mu.Lock()
	_, existed := r.agents[agentID]
	delete(r.agents, agentID)
	r.mu.Unlock()

	if existed {
		log.Printf("[ROUTER] ✗ Agent deregistered: %q (total: %d)", agentID, r.Count())
	}
}

func (r *Router) Get(agentID string) (*quic.Conn, error) {
	r.mu.RLock()
	ac, exists := r.agents[agentID]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent %q is not connected", agentID)
	}

	return ac.conn, nil
}

// ListAgents returns detailed connectivity info for all agents.
func (r *Router) ListAgents() []AgentInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]AgentInfo, 0, len(r.agents))
	for id, ac := range r.agents {
		infos = append(infos, AgentInfo{
			AgentID:     id,
			Uptime:      time.Since(ac.connectedAt).Round(time.Second).String(),
			ConnectedAt: ac.connectedAt,
		})
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].AgentID < infos[j].AgentID
	})
	return infos
}

// List remains for simple ID fetching.
func (r *Router) List() []string {
	infos := r.ListAgents()
	ids := make([]string, len(infos))
	for i, info := range infos {
		ids[i] = info.AgentID
	}
	return ids
}

func (r *Router) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

func (r *Router) watchConnection(agentID string, conn *quic.Conn) {
	<-conn.Context().Done()
	log.Printf("[ROUTER] ⚡ Connection lost for agent %q — scrubbing from routing table", agentID)
	r.Deregister(agentID)
}
