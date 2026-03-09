package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Cache provides distributed caching and rate limiting backed by etcd.
type Cache struct {
	client *clientv3.Client
	prefix string
}

// New creates a new etcd-backed cache.
// endpoints is a list of etcd endpoints (e.g., ["etcd:2379"]).
func New(endpoints []string, prefix string, dialTimeout time.Duration) (*Cache, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("etcd connect: %w", err)
	}

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	_, err = cli.Status(ctx, endpoints[0])
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("etcd health check: %w", err)
	}

	log.Printf("Connected to etcd at %v", endpoints)
	return &Cache{client: cli, prefix: prefix}, nil
}

// Close closes the etcd client connection.
func (c *Cache) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// --- Scan Result Caching ---

// GetScanResult retrieves a cached scan result by file SHA256 hash.
// Returns nil if not found or expired.
func (c *Cache) GetScanResult(ctx context.Context, sha256 string) ([]byte, error) {
	key := c.prefix + "scan:" + sha256
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("etcd get: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	return resp.Kvs[0].Value, nil
}

// SetScanResult stores a scan result with a TTL.
func (c *Cache) SetScanResult(ctx context.Context, sha256 string, data []byte, ttl time.Duration) error {
	key := c.prefix + "scan:" + sha256
	lease, err := c.client.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return fmt.Errorf("etcd lease grant: %w", err)
	}
	_, err = c.client.Put(ctx, key, string(data), clientv3.WithLease(lease.ID))
	if err != nil {
		return fmt.Errorf("etcd put: %w", err)
	}
	return nil
}

// --- Distributed Rate Limiting ---

// RateLimitEntry tracks request counts for an IP within a time window.
type RateLimitEntry struct {
	Count       int   `json:"count"`
	WindowStart int64 `json:"window_start"`
}

// CheckRateLimit atomically checks and increments the request count for an IP.
// Returns true if the request is allowed, false if rate limit exceeded.
func (c *Cache) CheckRateLimit(ctx context.Context, ip string, rpm int, windowSec int64) (bool, error) {
	key := c.prefix + "rl:" + ip
	now := time.Now().Unix()

	// Use a transaction to atomically read-modify-write
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("etcd get rate limit: %w", err)
	}

	var entry RateLimitEntry
	var modRevision int64

	if len(resp.Kvs) > 0 {
		modRevision = resp.Kvs[0].ModRevision
		if err := json.Unmarshal(resp.Kvs[0].Value, &entry); err != nil {
			// Corrupted entry, reset
			entry = RateLimitEntry{Count: 0, WindowStart: now}
		}
	}

	// Check if we're in a new window
	if now-entry.WindowStart >= windowSec {
		entry = RateLimitEntry{Count: 0, WindowStart: now}
	}

	if entry.Count >= rpm {
		return false, nil
	}

	entry.Count++
	data, err := json.Marshal(entry)
	if err != nil {
		return false, err
	}

	// Use etcd lease for auto-expiry
	lease, err := c.client.Grant(ctx, windowSec)
	if err != nil {
		return false, fmt.Errorf("etcd lease grant: %w", err)
	}

	if len(resp.Kvs) == 0 {
		// Key doesn't exist, create it
		txnResp, err := c.client.Txn(ctx).
			If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
			Then(clientv3.OpPut(key, string(data), clientv3.WithLease(lease.ID))).
			Else(clientv3.OpGet(key)).
			Commit()
		if err != nil {
			return false, fmt.Errorf("etcd txn: %w", err)
		}
		if !txnResp.Succeeded {
			// Another pod created the key; retry once with the new value
			return c.retryRateLimit(ctx, key, rpm, windowSec, lease.ID)
		}
	} else {
		// Key exists, compare-and-swap
		txnResp, err := c.client.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", modRevision)).
			Then(clientv3.OpPut(key, string(data), clientv3.WithLease(lease.ID))).
			Else(clientv3.OpGet(key)).
			Commit()
		if err != nil {
			return false, fmt.Errorf("etcd txn: %w", err)
		}
		if !txnResp.Succeeded {
			return c.retryRateLimit(ctx, key, rpm, windowSec, lease.ID)
		}
	}

	return true, nil
}

func (c *Cache) retryRateLimit(ctx context.Context, key string, rpm int, windowSec int64, leaseID clientv3.LeaseID) (bool, error) {
	now := time.Now().Unix()
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if len(resp.Kvs) == 0 {
		return true, nil
	}

	var entry RateLimitEntry
	if err := json.Unmarshal(resp.Kvs[0].Value, &entry); err != nil {
		return true, nil
	}

	if now-entry.WindowStart >= windowSec {
		entry = RateLimitEntry{Count: 1, WindowStart: now}
	} else {
		if entry.Count >= rpm {
			return false, nil
		}
		entry.Count++
	}

	data, _ := json.Marshal(entry)
	_, err = c.client.Put(ctx, key, string(data), clientv3.WithLease(leaseID))
	if err != nil {
		return false, err
	}
	return true, nil
}
