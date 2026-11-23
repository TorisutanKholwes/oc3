package worker

import (
	"testing"
	"time"
)

// The boot time of a node is the booted_at of its om3 node status, zero when
// the status does not say it.
func TestDaemonDataV3NodeBootedAt(t *testing.T) {
	d := &daemonDataV3{cluster: map[string]any{
		"node": map[string]any{
			"n1": map[string]any{"status": map[string]any{"booted_at": "2026-11-20T08:30:00.5+01:00"}},
			"n2": map[string]any{"status": map[string]any{}},
			"n3": map[string]any{"status": map[string]any{"booted_at": "yesterday"}},
			"n4": map[string]any{"status": map[string]any{"booted_at": 12}},
		},
	}}
	got, err := d.nodeBootedAt("n1")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 20, 7, 30, 0, 5e8, time.UTC); !got.Equal(want) {
		t.Errorf("n1: got %s, want %s", got, want)
	}
	for _, nodename := range []string{"n2", "n9"} {
		if got, err := d.nodeBootedAt(nodename); err != nil || !got.IsZero() {
			t.Errorf("%s: got %s %v, want zero", nodename, got, err)
		}
	}
	for _, nodename := range []string{"n3", "n4"} {
		if _, err := d.nodeBootedAt(nodename); err == nil {
			t.Errorf("%s: want an error", nodename)
		}
	}
}

// A v2 status does not say when the node booted.
func TestDaemonDataV2NodeBootedAt(t *testing.T) {
	if got, err := (&daemonDataV2{}).nodeBootedAt("n1"); err != nil || !got.IsZero() {
		t.Errorf("got %s %v, want zero", got, err)
	}
}

// A node booted after the dequeue of its action rebooted under it.
func TestBootedSince(t *testing.T) {
	dequeued := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	for title, c := range map[string]struct {
		bootedAt, dequeued time.Time
		want               bool
	}{
		"booted after the dequeue":   {dequeued.Add(time.Minute), dequeued, true},
		"booted before the dequeue":  {dequeued.Add(-24 * time.Hour), dequeued, false},
		"booted at the dequeue":      {dequeued, dequeued, false},
		"no boot time":               {time.Time{}, dequeued, false},
		"not dequeued":               {dequeued, time.Time{}, false},
		"another zone, booted after": {dequeued.Add(time.Minute).In(time.FixedZone("CET", 3600)), dequeued, true},
	} {
		if got := bootedSince(c.bootedAt, c.dequeued); got != c.want {
			t.Errorf("%s: got %v, want %v", title, got, c.want)
		}
	}
}
