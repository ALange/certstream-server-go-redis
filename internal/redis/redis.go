// Package redis provides functionality for writing decoded certificate entries to Redis.
package redis

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
	"github.com/d-Rickyy-b/certstream-server-go/internal/models"
)

const writeBufferSize = 5000

// Writer writes certificate entries to a Redis instance asynchronously.
type Writer struct {
	client    *goredis.Client
	keyPrefix string
	ttl       time.Duration
	writeChan chan []byte // buffered channel of (key\x00jsonValue) pairs encoded as "key\x00value"
	done      chan struct{}
}

// NewWriter creates a new Writer using the provided RedisConfig.
// It returns an error if the connection to Redis cannot be established.
// The Writer starts a background goroutine that drains the write queue.
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

	// Sanitize key prefix: remove any NUL bytes (used internally as separator) and trim whitespace.
	prefix := strings.ReplaceAll(strings.TrimSpace(cfg.KeyPrefix), "\x00", "")

	w := &Writer{
		client:    client,
		keyPrefix: prefix,
		ttl:       ttl,
		writeChan: make(chan []byte, writeBufferSize),
		done:      make(chan struct{}),
	}

	go w.drainWriteQueue()

	return w, nil
}

// Write enqueues a certificate entry for asynchronous storage in Redis.
// The key is composed of the configured prefix and the certificate's SHA256 fingerprint.
// If the internal write queue is full, the entry is dropped and a warning is logged.
func (w *Writer) Write(entry *models.Entry) {
	key := fmt.Sprintf("%s:%s", w.keyPrefix, entry.Data.LeafCert.SHA256)
	value := entry.JSON()

	// Encode key and value as "key\x00value" so we can pass both through the channel.
	payload := make([]byte, len(key)+1+len(value))
	copy(payload, key)
	payload[len(key)] = '\x00'
	copy(payload[len(key)+1:], value)

	select {
	case w.writeChan <- payload:
	default:
		log.Printf("Redis: write queue is full (%d), dropping certificate %s\n", writeBufferSize, key)
	}
}

// drainWriteQueue reads payloads from the write queue and stores them in Redis.
func (w *Writer) drainWriteQueue() {
	defer close(w.done)

	for payload := range w.writeChan {
		sep := strings.IndexByte(string(payload), '\x00')
		if sep < 0 {
			continue
		}

		key := string(payload[:sep])
		value := payload[sep+1:]

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := w.client.Set(ctx, key, value, w.ttl).Err()
		cancel()

		if err != nil {
			log.Printf("Redis: failed to write certificate %s: %v\n", key, err)
		}
	}
}

// Close stops the background writer goroutine and closes the underlying Redis connection.
// It waits for all pending writes in the queue to be processed before closing.
func (w *Writer) Close() {
	close(w.writeChan)
	<-w.done

	if err := w.client.Close(); err != nil {
		log.Printf("Redis: error closing connection: %v\n", err)
	}
}
