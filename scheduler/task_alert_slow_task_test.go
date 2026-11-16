package scheduler

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/opensvc/oc3/cachekeys"
)

func TestCountSlowFeeds(t *testing.T) {
	mr := miniredis.RunT(t)
	r := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = r.Close() })
	now := time.Now()
	old := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	recent := strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)
	mr.HSet(cachekeys.FeedDaemonStatusPendingH, "n1", old, "n2", recent)
	mr.HSet(cachekeys.FeedSystemPendingH, "n3", old)
	// queued by a feeder of before, valued by its index
	mr.HSet(cachekeys.FeedNodeChecksPendingH, "n4", "n4")

	n, err := countSlowFeeds(context.Background(), r, now.Add(-slowFeedWait))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("got %d slow feeds, want 2", n)
	}
}
