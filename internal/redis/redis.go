// Package redis provides functionality for writing decoded certificate entries to Redis.
package redis

import (
	"context"
	"fmt"
	"log"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

// Writer writes certificate entries to a Redis instance.
type Writer struct {
	client    *goredis.Client
	keyPrefix string
	ttl       time.Duration
}

// NewWriter creates a new Writer using the provided RedisConfig.
// It returns an error if the connection to Redis cannot be established.
func NewWriter(cfg config.RedisConfig) (*Writer, error) {
	client := goredis.NewClient(&goredis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("could not connect to Redis at %s: %w", cfg.Addr, err)
	}

	var ttl time.Duration
	if cfg.TTL > 0 {
		ttl = time.Duration(cfg.TTL) * time.Second
	}

	return &Writer{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
		ttl:       ttl,
	}, nil
}

// Write stores the JSON-encoded certificate entry in Redis.
// The key is composed of the configured prefix and the certificate's SHA256 fingerprint.
// The record expires after the configured TTL (0 means no expiry).
func (w *Writer) Write(entry *models.Entry) {
	key := fmt.Sprintf("%s:%s", w.keyPrefix, entry.Data.LeafCert.SHA256)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := w.client.Set(ctx, key, entry.JSON(), w.ttl).Err(); err != nil {
		log.Printf("Redis: failed to write certificate %s: %v\n", key, err)
	}
}

// Close closes the underlying Redis connection.
func (w *Writer) Close() {
	if err := w.client.Close(); err != nil {
		log.Printf("Redis: error closing connection: %v\n", err)
	}
}
