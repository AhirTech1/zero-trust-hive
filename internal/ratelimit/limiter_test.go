package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLimiter_Allow(t *testing.T) {
	l := New(60)
	subject := "test-agent"

	// First 60 requests should be allowed
	for i := 0; i < 60; i++ {
		if !l.Allow(subject) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 61st request should be denied
	if l.Allow(subject) {
		t.Fatal("request 61 should be denied")
	}
}

func TestLimiter_IndependentSubjects(t *testing.T) {
	l := New(5)

	// Exhaust subject A
	for i := 0; i < 5; i++ {
		l.Allow("subject-a")
	}

	// Subject B should still be allowed
	if !l.Allow("subject-b") {
		t.Fatal("subject-b should still have tokens")
	}

	// Subject A should be denied
	if l.Allow("subject-a") {
		t.Fatal("subject-a should be exhausted")
	}
}

func TestLimiter_ZeroRate(t *testing.T) {
	l := New(0) // should default to 60
	subject := "test"
	for i := 0; i < 60; i++ {
		if !l.Allow(subject) {
			t.Fatalf("request %d should be allowed with default rate", i+1)
		}
	}
}

func TestRateLimitMiddleware_NoSubject(t *testing.T) {
	l := New(1)
	handler := RateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No subject in context — should pass through
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_WithSubject(t *testing.T) {
	l := New(1)
	handler := RateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	subject := "test-subject"

	// First request with subject — allowed
	ctx := context.WithValue(context.Background(), SubjectKey, subject)
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec.Code)
	}

	// Second request with same subject — denied (rate limit 1)
	ctx2 := context.WithValue(context.Background(), SubjectKey, subject)
	req2 := httptest.NewRequest("GET", "/", nil).WithContext(ctx2)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestLimiter_Stop(t *testing.T) {
	l := New(60)
	l.Stop()
	l.Stop() // should not panic on double stop
}