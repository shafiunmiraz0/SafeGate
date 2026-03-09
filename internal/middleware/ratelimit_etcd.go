package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/YourName/safegate/internal/cache"
)

// EtcdRateLimiter provides distributed per-IP rate limiting backed by etcd.
type EtcdRateLimiter struct {
	cache   *cache.Cache
	rpm     int
	trusted map[string]bool
}

// NewEtcdRateLimiter creates a distributed rate limiter using etcd.
func NewEtcdRateLimiter(c *cache.Cache, rpm int, trustedProxies []string) *EtcdRateLimiter {
	trusted := make(map[string]bool, len(trustedProxies))
	for _, p := range trustedProxies {
		trusted[p] = true
	}
	return &EtcdRateLimiter{cache: c, rpm: rpm, trusted: trusted}
}

func (rl *EtcdRateLimiter) Allow(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	allowed, err := rl.cache.CheckRateLimit(ctx, ip, rl.rpm, 60)
	if err != nil {
		log.Printf("etcd rate limit error (allowing request): %v", err)
		return true // fail-open: allow request if etcd is unavailable
	}
	return allowed
}

// Middleware returns an HTTP middleware that enforces the distributed rate limit.
func (rl *EtcdRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, rl.trusted)

		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Rate limit exceeded. Try again later.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
