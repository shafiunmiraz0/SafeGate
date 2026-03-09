package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/YourName/safegate/internal/cache"
	"github.com/YourName/safegate/internal/config"
	"github.com/YourName/safegate/internal/handler"
	"github.com/YourName/safegate/internal/middleware"
	"github.com/YourName/safegate/internal/scanner"
)

func main() {
	// Load .env file if present (ignored in production/Docker)
	_ = godotenv.Load()

	cfg := config.Load()

	// Validate API key strength
	if cfg.APIKey == "" {
		log.Println("WARNING: No API key configured — authentication is DISABLED. Set SAFEGATE_API_KEY for production.")
	} else if len(cfg.APIKey) < 32 {
		log.Println("WARNING: API key is shorter than 32 characters. Use a strong, random key for production.")
	}

	// Build scanner pipeline
	scanners := []scanner.Scanner{
		scanner.NewMetadataScanner(cfg.MaxFileSize),
		scanner.NewMIMEScanner(cfg.AllowedTypes),
		scanner.NewSVGScanner(),
		scanner.NewMacroScanner(),
		scanner.NewArchiveScanner(cfg.MaxArchiveDepth, cfg.MaxArchiveSize),
	}

	if cfg.ClamAVEnabled {
		scanners = append(scanners, scanner.NewClamAVScanner(cfg.ClamAVAddr))
		log.Printf("ClamAV enabled at %s", cfg.ClamAVAddr)
	} else {
		log.Println("ClamAV disabled — running without antivirus scanning")
	}

	orchestrator := scanner.NewOrchestrator(scanners...)

	// Initialize etcd cache (optional)
	var etcdCache *cache.Cache
	if cfg.EtcdEnabled {
		var err error
		etcdCache, err = cache.New(
			cfg.EtcdEndpoints,
			cfg.EtcdPrefix,
			time.Duration(cfg.EtcdDialTimeout)*time.Second,
		)
		if err != nil {
			log.Printf("WARNING: Failed to connect to etcd: %v — running without distributed cache", err)
		} else {
			log.Printf("Etcd enabled at %v (prefix: %s, cache TTL: %ds)", cfg.EtcdEndpoints, cfg.EtcdPrefix, cfg.CacheTTL)
			defer etcdCache.Close()
		}
	} else {
		log.Println("Etcd disabled — using in-memory rate limiting, no scan caching")
	}

	scanHandler := handler.NewScanHandler(orchestrator, cfg.MaxFileSize, etcdCache, time.Duration(cfg.CacheTTL)*time.Second)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/api/v1/scan", scanHandler.HandleScan)

	// Middleware stack (applied in reverse order)
	var h http.Handler = mux

	// Per-request timeout
	h = middleware.RequestTimeout(cfg.RequestTimeout, h)

	// Authentication (health endpoint is public)
	h = middleware.APIKeyAuth(cfg.APIKey, []string{"/health"}, h)

	// Rate limiting
	if cfg.RateLimitRPM > 0 {
		if etcdCache != nil {
			etcdLimiter := middleware.NewEtcdRateLimiter(etcdCache, cfg.RateLimitRPM, cfg.TrustedProxies)
			h = etcdLimiter.Middleware(h)
			log.Printf("Distributed rate limiting enabled: %d requests/minute per IP (etcd-backed)", cfg.RateLimitRPM)
		} else {
			limiter := middleware.NewRateLimiter(cfg.RateLimitRPM, cfg.TrustedProxies)
			h = limiter.Middleware(h)
			log.Printf("In-memory rate limiting enabled: %d requests/minute per IP", cfg.RateLimitRPM)
		}
	}

	// CORS
	h = middleware.CORS(cfg.CORSAllowedOrigins, h)

	// Security headers
	h = middleware.SecurityHeaders(h)

	// Request ID + logging (outermost)
	h = middleware.RequestID(h)
	h = middleware.RequestLogger(h)

	addr := ":" + cfg.Port
	log.Printf("SafeGate starting on %s", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.IdleTimeout) * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Server error: %v", err)
		os.Exit(1)
	}
}
