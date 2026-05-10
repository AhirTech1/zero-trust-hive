package audit

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestLogger_Enabled(t *testing.T) {
	l := New(true)
	if !l.Enabled() {
		t.Fatal("should be enabled")
	}

	l2 := New(false)
	if l2.Enabled() {
		t.Fatal("should be disabled")
	}
}

func TestLogger_Record_Disabled(t *testing.T) {
	l := New(false)
	l.Record(Entry{
		Timestamp: time.Now(),
		Subject:   "test",
		Status:    "ok",
	})
	// Should not panic or write
}

func TestLogger_Record_Concurrent(t *testing.T) {
	l := New(true)

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				l.Record(Entry{
					Timestamp:  time.Now(),
					Subject:    "test-subject",
					AgentID:    "agent-001",
					Command:    "uptime",
					FirewallOK: true,
					Status:     "ok",
					DurationMs: 42,
				})
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestLogger_Record_Output(t *testing.T) {
	var buf bytes.Buffer

	l := &Logger{
		enabled: true,
		logger:  log.New(&buf, "", 0),
	}

	entry := Entry{
		Timestamp:  time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		Subject:    "langchain-agent",
		AgentID:    "prod-01",
		Command:    "uptime",
		FirewallOK: true,
		Status:     "ok",
		DurationMs: 150,
	}

	l.Record(entry)

	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("expected JSON output")
	}

	if !strings.Contains(output, `"subject":"langchain-agent"`) {
		t.Errorf("output missing subject: %s", output)
	}
	if !strings.Contains(output, `"status":"ok"`) {
		t.Errorf("output missing status: %s", output)
	}
}