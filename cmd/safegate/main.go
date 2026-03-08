package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/YourName/safegate/internal/config"
	"github.com/YourName/safegate/internal/handler"
	"github.com/YourName/safegate/internal/middleware"
	"github.com/YourName/safegate/internal/scanner"
)

func main() {
	// Load .env file if present (ignored in production/Docker)
	_ = godotenv.Load()

	cfg := config.Load()

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
	scanHandler := handler.NewScanHandler(orchestrator, cfg.MaxFileSize)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.HandleHealth)
	mux.HandleFunc("/api/v1/scan", scanHandler.HandleScan)

	// Middleware stack
	var h http.Handler = mux
	h = middleware.APIKeyAuth(cfg.APIKey, h)
	h = middleware.CORS(h)
	h = middleware.RequestLogger(h)

	addr := ":" + cfg.Port
	log.Printf("SafeGate starting on %s", addr)

	if err := http.ListenAndServe(addr, h); err != nil {
		log.Printf("Server error: %v", err)
		os.Exit(1)
	}
}
