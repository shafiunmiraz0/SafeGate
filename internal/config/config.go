package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port            string
	APIKey          string
	MaxFileSize     int64    // bytes
	AllowedTypes    []string // allowed MIME types
	ClamAVAddr      string   // ClamAV TCP address (host:port)
	ClamAVEnabled   bool
	TempDir         string
	MaxArchiveDepth int
	MaxArchiveSize  int64 // max decompressed size to prevent zip bombs

	// Security settings
	CORSAllowedOrigins []string // allowed CORS origins (empty = block all cross-origin)
	RateLimitRPM       int      // max requests per minute per IP (0 = disabled)
	ReadTimeout        int      // HTTP server read timeout in seconds
	WriteTimeout       int      // HTTP server write timeout in seconds
	IdleTimeout        int      // HTTP server idle timeout in seconds
	RequestTimeout     int      // per-request context timeout in seconds
	TrustedProxies     []string // trusted proxy IPs for X-Forwarded-For

	// Etcd settings
	EtcdEndpoints   []string // etcd endpoints (e.g., ["etcd:2379"])
	EtcdEnabled     bool     // enable etcd for distributed caching/rate limiting
	EtcdDialTimeout int      // etcd dial timeout in seconds
	EtcdPrefix      string   // key prefix for etcd entries
	CacheTTL        int      // scan result cache TTL in seconds
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:            getEnv("SAFEGATE_PORT", "8443"),
		APIKey:          getEnv("SAFEGATE_API_KEY", ""),
		MaxFileSize:     getEnvInt64("SAFEGATE_MAX_FILE_SIZE", 50*1024*1024), // 50MB
		AllowedTypes:    getEnvSlice("SAFEGATE_ALLOWED_TYPES", defaultAllowedTypes()),
		ClamAVAddr:      getEnv("SAFEGATE_CLAMAV_ADDR", "clamav:3310"),
		ClamAVEnabled:   getEnvBool("SAFEGATE_CLAMAV_ENABLED", true),
		TempDir:         getEnv("SAFEGATE_TEMP_DIR", os.TempDir()),
		MaxArchiveDepth: getEnvInt("SAFEGATE_MAX_ARCHIVE_DEPTH", 3),
		MaxArchiveSize:  getEnvInt64("SAFEGATE_MAX_ARCHIVE_SIZE", 200*1024*1024), // 200MB

		CORSAllowedOrigins: getEnvSlice("SAFEGATE_CORS_ORIGINS", nil),
		RateLimitRPM:        getEnvInt("SAFEGATE_RATE_LIMIT_RPM", 60),
		ReadTimeout:         getEnvInt("SAFEGATE_READ_TIMEOUT", 30),
		WriteTimeout:        getEnvInt("SAFEGATE_WRITE_TIMEOUT", 60),
		IdleTimeout:         getEnvInt("SAFEGATE_IDLE_TIMEOUT", 120),
		RequestTimeout:      getEnvInt("SAFEGATE_REQUEST_TIMEOUT", 300),
		TrustedProxies:      getEnvSlice("SAFEGATE_TRUSTED_PROXIES", nil),

		EtcdEndpoints:   getEnvSlice("SAFEGATE_ETCD_ENDPOINTS", []string{"etcd:2379"}),
		EtcdEnabled:     getEnvBool("SAFEGATE_ETCD_ENABLED", false),
		EtcdDialTimeout: getEnvInt("SAFEGATE_ETCD_DIAL_TIMEOUT", 5),
		EtcdPrefix:      getEnv("SAFEGATE_ETCD_PREFIX", "/safegate/"),
		CacheTTL:        getEnvInt("SAFEGATE_CACHE_TTL", 3600),
	}
}

func defaultAllowedTypes() []string {
	return []string{
		"application/pdf",
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"application/zip",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"text/plain",
		"text/csv",
		"application/json",
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

func getEnvInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return i
}

func getEnvSlice(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}
