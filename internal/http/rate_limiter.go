package ui

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxLoginAttempts = 5
	defaultLockDuration     = 60 * time.Second
	rateLimiterCleanupAfter = 10 * time.Minute
)

// loginRecord tracks failed login attempts for a single remote IP.
type loginRecord struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

// RateLimiter enforces a maximum number of consecutive failed login attempts
// per remote IP address. After maxAttempts failures the IP is locked out for
// lockDuration. Expired records are pruned lazily during RecordFailure calls
// to bound memory usage without requiring a background goroutine.
//
// Only the direct peer address (r.RemoteAddr) is used as key to prevent
// trivial bypass via X-Forwarded-For spoofing.
type RateLimiter struct {
	mu           sync.Mutex
	records      map[string]*loginRecord
	maxAttempts  int
	lockDuration time.Duration
}

// NewRateLimiter creates a RateLimiter with the default limits:
// 5 consecutive failures trigger a 60-second lockout.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		records:      make(map[string]*loginRecord),
		maxAttempts:  defaultMaxLoginAttempts,
		lockDuration: defaultLockDuration,
	}
}

// peerIP extracts the bare IP address from r.RemoteAddr, discarding the port.
func peerIP(r *http.Request) string {
	addr := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// IsLocked returns true if the request's remote IP is currently locked out.
func (rl *RateLimiter) IsLocked(r *http.Request) bool {
	ip := peerIP(r)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rec, ok := rl.records[ip]
	if !ok {
		return false
	}
	return time.Now().Before(rec.lockedUntil)
}

// RecordFailure increments the failure counter for the request's remote IP.
// Once maxAttempts is reached the IP is locked for lockDuration and the
// counter is reset so subsequent attempts renew the lock cleanly.
// Expired records that have not been seen recently are pruned at the start
// of each call.
func (rl *RateLimiter) RecordFailure(r *http.Request) {
	ip := peerIP(r)
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.pruneExpiredLocked(now)

	rec, ok := rl.records[ip]
	if !ok {
		rec = &loginRecord{}
		rl.records[ip] = rec
	}

	rec.failures++
	rec.lastSeen = now
	if rec.failures >= rl.maxAttempts {
		rec.lockedUntil = now.Add(rl.lockDuration)
		rec.failures = 0
	}
}

// RecordSuccess clears any failure record for the request's remote IP after
// a successful login.
func (rl *RateLimiter) RecordSuccess(r *http.Request) {
	ip := peerIP(r)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.records, ip)
}

// pruneExpiredLocked removes records whose lockout has expired and that have
// not been seen within rateLimiterCleanupAfter. Must be called with rl.mu held.
func (rl *RateLimiter) pruneExpiredLocked(now time.Time) {
	for ip, rec := range rl.records {
		if now.After(rec.lockedUntil) && now.Sub(rec.lastSeen) > rateLimiterCleanupAfter {
			delete(rl.records, ip)
		}
	}
}
