package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

const cleanupInterval = 5 * time.Minute

// tokenBucket tracks available tokens for a single subject.
type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter provides per-subject rate limiting using a token bucket algorithm.
// Subjects that exceed the rate receive false from Allow().
// A background goroutine cleans up stale buckets periodically.
type Limiter struct {
	rate       float64 // tokens per second
	burst      int     // max tokens (bucket size)
	buckets    sync.Map
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// New creates a rate limiter with the given requests-per-minute rate.
// The burst size equals the rate so a subject can burst up to a full
// minute's worth of tokens.
func New(reqPerMinute int) *Limiter {
	if reqPerMinute <= 0 {
		reqPerMinute = 60
	}

	l := &Limiter{
		rate:   float64(reqPerMinute) / 60.0,
		burst:  reqPerMinute,
		stopCh: make(chan struct{}),
	}

	go l.cleanup()
	return l
}

// Allow returns true if the subject is within their rate limit.
// The subject is typically the JWT "sub" claim.
func (l *Limiter) Allow(subject string) bool {
	now := time.Now()

	val, _ := l.buckets.LoadOrStore(subject, &tokenBucket{
		tokens:   float64(l.burst),
		lastSeen: now,
	})

	bucket := val.(*tokenBucket)

	// This is intentionally not a mutex — token bucket refill is
	// approximate under high contention, which is acceptable for rate limiting.
	elapsed := now.Sub(bucket.lastSeen).Seconds()
	bucket.tokens += elapsed * l.rate
	if bucket.tokens > float64(l.burst) {
		bucket.tokens = float64(l.burst)
	}
	bucket.lastSeen = now

	if bucket.tokens < 1.0 {
		return false
	}

	bucket.tokens--
	return true
}

// RateLimitMiddleware returns an HTTP middleware that rate-limits by JWT subject.
// The subject is extracted from the request context — callers should set it
// before calling this middleware.
func RateLimitMiddleware(limiter *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := r.Context().Value(SubjectKey)
			if subject == nil {
				next.ServeHTTP(w, r)
				return
			}

			if !limiter.Allow(subject.(string)) {
				w.Header().Set("Retry-After", "60")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"status":"error","error":"rate limit exceeded — slow down"}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			l.buckets.Range(func(key, value interface{}) bool {
				bucket := value.(*tokenBucket)
				if now.Sub(bucket.lastSeen) > cleanupInterval {
					l.buckets.Delete(key)
				}
				return true
			})
		case <-l.stopCh:
			return
		}
	}
}

// Stop shuts down the cleanup goroutine.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
}

// contextKey is used to pass subject through request context.
type contextKey string

// SubjectKey is the context key for storing the JWT subject.
const SubjectKey contextKey = "jwt-subject"