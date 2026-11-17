package cdb

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestResmonPurgeExpired checks the resources of the instances a daemon status
// reports unchanged are kept, not having been rewritten, and the others not
// written since the report are deleted, their current status log ended.
func TestResmonPurgeExpired(t *testing.T) {
	db := testMariaDB(t,
		"CREATE TABLE resmon (id INT AUTO_INCREMENT PRIMARY KEY, svc_id CHAR(36), node_id CHAR(36), vmname VARCHAR(255) DEFAULT '', rid VARCHAR(255), updated DATETIME)",
		"CREATE TABLE resmon_log_last (id INT AUTO_INCREMENT PRIMARY KEY, svc_id CHAR(36), node_id CHAR(36), rid VARCHAR(255), res_end DATETIME)",
		// s1@n1 unchanged; s2@n1 rewritten, fs#1 gone; s3@n1 absent from the report; n2 not in the report
		"INSERT INTO resmon (svc_id, node_id, rid, updated) VALUES"+
			" ('s1', 'n1', 'ip#0', NOW() - INTERVAL 1 HOUR),"+
			" ('s2', 'n1', 'fs#0', NOW()), ('s2', 'n1', 'fs#1', NOW() - INTERVAL 1 HOUR),"+
			" ('s3', 'n1', 'app#0', NOW() - INTERVAL 1 HOUR),"+
			" ('s1', 'n2', 'ip#0', NOW() - INTERVAL 1 HOUR)",
		"INSERT INTO resmon_log_last (svc_id, node_id, rid, res_end) VALUES ('s2', 'n1', 'fs#1', NOW() - INTERVAL 1 HOUR), ('s1', 'n1', 'ip#0', NOW() - INTERVAL 1 HOUR)",
	)
	odb := New(db)
	odb.Metrics = testMetrics()
	odb.Session = NewSession(db, nil)
	ctx := context.Background()
	if err := odb.ResmonPurgeExpired(ctx, time.Now().Add(-time.Minute), []string{"n1"}, map[string][]string{"n1": {"s1"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT CONCAT(svc_id, '@', node_id, ':', rid) FROM resmon ORDER BY svc_id, node_id, rid")
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		left = append(left, s)
	}
	_ = rows.Close()
	if want := []string{"s1@n1:ip#0", "s1@n2:ip#0", "s2@n1:fs#0"}; !slices.Equal(left, want) {
		t.Errorf("resources left %v, want %v", left, want)
	}
	var ended, kept int
	if err := db.QueryRow("SELECT SUM(rid = 'fs#1' AND res_end > NOW() - INTERVAL 1 MINUTE), SUM(rid = 'ip#0' AND res_end < NOW() - INTERVAL 30 MINUTE) FROM resmon_log_last").Scan(&ended, &kept); err != nil {
		t.Fatal(err)
	}
	if ended != 1 || kept != 1 {
		t.Errorf("log ends: gone ended %d, kept untouched %d, want 1 and 1", ended, kept)
	}
}
