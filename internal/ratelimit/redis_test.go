package ratelimit

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// testCounter connects to the Redis in TEST_REDIS_URL. Without it, the
// test is skipped.
func testCounter(t *testing.T) (*RedisCounter, *redis.Client) {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set; skipping Redis test")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(opts)
	t.Cleanup(func() { client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	return NewRedisCounter(client), client
}

// uniqueID gives each test run its own system ID, so runs don't share counts.
func uniqueID() string {
	return fmt.Sprintf("test-%d", rand.Int63())
}

func TestRedisCountsPerWindow(t *testing.T) {
	c, client := testCounter(t)
	ctx := context.Background()
	id := uniqueID()

	for want := int64(1); want <= 3; want++ {
		got, reset, err := c.Hit(ctx, id, at10s)
		if err != nil || got != want {
			t.Fatalf("Hit = %d, %v; want %d", got, err, want)
		}
		if !reset.Equal(at10s.Truncate(time.Minute).Add(time.Minute)) {
			t.Errorf("reset = %v, want the end of the minute", reset)
		}
	}

	// The next minute is a fresh window; another system has its own count.
	if got, _, _ := c.Hit(ctx, id, at10s.Add(time.Minute)); got != 1 {
		t.Errorf("next minute: count = %d, want 1", got)
	}
	if got, _, _ := c.Hit(ctx, uniqueID(), at10s); got != 1 {
		t.Errorf("other system: count = %d, want 1", got)
	}

	// Every key gets an expiry, so Redis cleans up after itself.
	key := fmt.Sprintf("aigov:ratelimit:%s:%d", id, at10s.Truncate(time.Minute).Unix())
	if ttl := client.TTL(ctx, key).Val(); ttl <= 0 || ttl > 2*time.Minute {
		t.Errorf("TTL = %v, want between 0 and 2 minutes", ttl)
	}
}

func TestRedisConcurrentHitsAreAllCounted(t *testing.T) {
	c, _ := testCounter(t)
	id := uniqueID()
	const n = 50

	var wg sync.WaitGroup
	seen := make(chan int64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _, err := c.Hit(context.Background(), id, at10s)
			if err != nil {
				t.Error(err)
			}
			seen <- got
		}()
	}
	wg.Wait()
	close(seen)

	// Each request must get its own number from 1 to n: no lost updates.
	unique := map[int64]bool{}
	for v := range seen {
		unique[v] = true
	}
	if len(unique) != n {
		t.Errorf("got %d distinct counts from %d concurrent hits, want %d", len(unique), n, n)
	}
}
