package scheduler

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

// The grace a shutdown node is given to go silent is a max_age setting, of at
// least a minute.
func TestCloseShutdownMaxAge(t *testing.T) {
	const key = "scheduler.task.close_shutdown.max_age"
	// Restored to its default rather than unset: a key set to nil stays known
	// to viper, empty, which ValidateMaxAges refuses in the tests after.
	defer viper.Set(key, "5m")
	cases := []struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"5m", 5 * time.Minute, false},
		{"1h", time.Hour, false},
		{"30s", 0, true},
		{"soon", 0, true},
	}
	for _, c := range cases {
		viper.Set(key, c.value)
		got, err := maxAge("close_shutdown")
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", c.value, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %s, want %s", c.value, got, c.want)
		}
	}
}
