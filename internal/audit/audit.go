package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// Entry is a single audit record for a command dispatch event.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Subject    string    `json:"subject"`
	AgentID    string    `json:"agent_id"`
	Command    string    `json:"command"`
	FirewallOK bool      `json:"firewall_ok"`
	Status     string    `json:"status"` // "ok", "blocked", "error", "timeout"
	DurationMs int64     `json:"duration_ms"`
}

// Logger writes structured audit log entries to stderr.
// All methods are safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	enabled bool
	logger *log.Logger
}

// New creates a new audit Logger. Set enabled to false to no-op all writes.
func New(enabled bool) *Logger {
	return &Logger{
		enabled: enabled,
		logger:  log.New(os.Stderr, "", 0),
	}
}

// Record writes an audit entry as a JSON line to stderr.
// Does nothing if the logger is disabled.
func (l *Logger) Record(entry Entry) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback: write a broken-entry marker
		l.logger.Printf(`{"error":"marshal_failed","timestamp":"%s"}`+"\n", time.Now().Format(time.RFC3339))
		return
	}
	l.logger.Println(string(data))
}

// Enabled returns true if audit logging is active.
func (l *Logger) Enabled() bool {
	return l.enabled
}