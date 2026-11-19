// Package ratelimit limits how many requests each AI system can make per
// minute, so one runaway system can't flood the providers, run up costs,
// or starve the others.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Counter counts one request for a system in the current one-minute
// window, and returns the count so far and when the window ends.
type Counter interface {
	Hit(ctx context.Context, systemID string, now time.Time) (count int64, resetAt time.Time, err error)
}

// RedisCounter keeps the counts in Redis, so every gateway instance
// shares the same limit.
type RedisCounter struct {
	client *redis.Client
}

func NewRedisCounter(client *redis.Client) *RedisCounter {
	return &RedisCounter{client: client}
}

// Hit uses a fixed one-minute window: one Redis key per system per
// minute, counted with INCR. The key expires on its own soon after its
// minute is over, so nothing needs cleaning up.
func (c *RedisCounter) Hit(ctx context.Context, systemID string, now time.Time) (int64, time.Time, error) {
	window := now.UTC().Truncate(time.Minute)
	key := fmt.Sprintf("aigov:ratelimit:%s:%d", systemID, window.Unix())

	// MULTI/EXEC: the increment and the expiry happen together, so a key
	// can never be left behind without an expiry.
	pipe := c.client.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 2*time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, time.Time{}, fmt.Errorf("ratelimit: %w", err)
	}
	return incr.Val(), window.Add(time.Minute), nil
}
