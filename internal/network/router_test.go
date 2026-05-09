package network

import (
	"testing"
)

func TestRouter_RegisterAndGet(t *testing.T) {
	r := NewRouter()

	// Can't test Get with a real QUIC connection without network setup,
	// but we can test Count, List, and Deregister.

	if r.Count() != 0 {
		t.Errorf("expected 0 agents, got %d", r.Count())
	}
}

func TestRouter_List(t *testing.T) {
	r := NewRouter()

	ids := r.List()
	if len(ids) != 0 {
		t.Errorf("expected empty list, got %v", ids)
	}
}

func TestRouter_Deregister(t *testing.T) {
	r := NewRouter()

	// Deregistering a non-existent agent should not panic
	r.Deregister("nonexistent")
	if r.Count() != 0 {
		t.Errorf("expected 0 agents after no-op deregister, got %d", r.Count())
	}
}

func TestRouter_Get_NotFound(t *testing.T) {
	r := NewRouter()

	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestRouter_Count_Empty(t *testing.T) {
	r := NewRouter()

	if r.Count() != 0 {
		t.Errorf("new router should have 0 agents")
	}
}

func TestRouter_ListAgents_Empty(t *testing.T) {
	r := NewRouter()

	agents := r.ListAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}