package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIKeyAuth validates the X-API-Key header against the configured key.
// Requests to paths in skipPaths bypass authentication.
func APIKeyAuth(apiKey string, skipPaths []string, next http.Handler) http.Handler {
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if skip[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth if no API key is configured
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get("X-API-Key")
		if key == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Invalid or missing API key",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds standard security headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0") // modern browsers; CSP is preferred
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")

		next.ServeHTTP(w, r)
	})
}

// RequestID generates a unique ID for each request and adds it to the
// response header and request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := generateRequestID()
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxKey string

const requestIDKey ctxKey = "request_id"

// GetRequestID returns the request ID from the context, if any.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RequestLogger logs incoming requests with timing and request ID.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}

		next.ServeHTTP(wrapped, r)

		reqID := GetRequestID(r.Context())
		log.Printf("[%s] %s %s %d %s %s", reqID, r.Method, r.URL.Path, wrapped.status, time.Since(start), clientIP(r, nil))
	})
}

// RequestTimeout applies a context deadline to each request.
func RequestTimeout(seconds int, next http.Handler) http.Handler {
	if seconds <= 0 {
		return next
	}
	d := time.Duration(seconds) * time.Second
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CORS adds Cross-Origin Resource Sharing headers with configurable origins.
// If allowedOrigins is nil/empty, no CORS headers are set (blocks cross-origin).
func CORS(allowedOrigins []string, next http.Handler) http.Handler {
	origins := make(map[string]bool, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		origins[strings.ToLower(o)] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (allowAll || origins[strings.ToLower(origin)]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitChecker is the interface for checking rate limits.
// Both in-memory and etcd-backed implementations satisfy this.
type RateLimitChecker interface {
	Allow(ip string) bool
}

// RateLimiter provides per-IP request rate limiting using a token bucket.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rpm      int // requests per minute
	trusted  map[string]bool
}

type visitor struct {
	tokens     float64
	lastSeen   time.Time
	maxTokens  float64
	refillRate float64 // tokens per second
}

// NewRateLimiter creates a rate limiter allowing rpm requests per minute per IP.
func NewRateLimiter(rpm int, trustedProxies []string) *RateLimiter {
	trusted := make(map[string]bool, len(trustedProxies))
	for _, p := range trustedProxies {
		trusted[p] = true
	}
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rpm:      rpm,
		trusted:  trusted,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 5*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) getVisitor(ip string) *visitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		maxTokens := float64(rl.rpm)
		v = &visitor{
			tokens:     maxTokens,
			lastSeen:   time.Now(),
			maxTokens:  maxTokens,
			refillRate: maxTokens / 60.0,
		}
		rl.visitors[ip] = v
		return v
	}

	// Refill tokens based on elapsed time
	elapsed := time.Since(v.lastSeen).Seconds()
	v.tokens += elapsed * v.refillRate
	if v.tokens > v.maxTokens {
		v.tokens = v.maxTokens
	}
	v.lastSeen = time.Now()
	return v
}

func (rl *RateLimiter) allow(ip string) bool {
	v := rl.getVisitor(ip)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if v.tokens >= 1 {
		v.tokens--
		return true
	}
	return false
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.allow(ip)
}

// Middleware returns an HTTP middleware that enforces the rate limit.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, rl.trusted)

		if !rl.allow(ip) {
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

// clientIP extracts the real client IP, respecting trusted proxies.
func clientIP(r *http.Request, trusted map[string]bool) string {
	// Only trust X-Forwarded-For from known proxies
	if len(trusted) > 0 {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if trusted[remoteIP] {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				// Return the leftmost (original client) IP
				return strings.TrimSpace(parts[0])
			}
			if xri := r.Header.Get("X-Real-IP"); xri != "" {
				return strings.TrimSpace(xri)
			}
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
