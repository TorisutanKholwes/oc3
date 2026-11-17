package cdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// testMariaDB is a new database of the MariaDB server OC3_TEST_MYSQL_DSN
// names, holding the tables statements create, dropped at the end of the
// test. Its connections interpolate the arguments, as those of the collector.
func testMariaDB(t *testing.T, statements ...string) *sql.DB {
	t.Helper()
	dsn := os.Getenv("OC3_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("OC3_TEST_MYSQL_DSN is not set, as root:pass@tcp(127.0.0.1:3306)/: no MariaDB to test against")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ParseTime = true
	cfg.Loc = time.Local
	cfg.InterpolateParams = true
	cfg.DBName = ""
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("oc3_test_cdb_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE " + name) })
	cfg.DBName = name
	pool, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	for _, s := range statements {
		if _, err := pool.Exec(s); err != nil {
			t.Fatalf("%s: %s", s, err)
		}
	}
	return pool
}

// The tables of the collector the dashboard producers read, reduced to the
// columns they use; dashboard as in the collector.
var dashboardTestTables = []string{
	"CREATE TABLE dashboard (" +
		" id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY," +
		" dash_type varchar(60) NOT NULL DEFAULT ''," +
		" svc_id char(36) CHARACTER SET ascii DEFAULT ''," +
		" dash_severity tinyint NOT NULL," +
		" dash_fmt varchar(100) DEFAULT ''," +
		" dash_dict text DEFAULT ''," +
		" dash_created timestamp NOT NULL DEFAULT current_timestamp()," +
		" dash_dict_md5 varchar(32) DEFAULT ''," +
		" dash_env enum('PRD','PPRD','REC','INT','DEV','TST','TMP','DRP','FOR','PRA','PRJ','') DEFAULT NULL," +
		" dash_updated datetime DEFAULT NULL," +
		" node_id char(36) CHARACTER SET ascii DEFAULT ''," +
		" dash_md5 binary(32) GENERATED ALWAYS AS (md5(concat(dash_type, if(dash_instance is null, '', dash_instance)))) STORED," +
		" dash_instance varchar(180) DEFAULT ''," +
		" UNIQUE KEY idx1 (svc_id, node_id, dash_md5))",
	"CREATE TABLE nodes (node_id char(36) CHARACTER SET ascii PRIMARY KEY, nodename varchar(256), node_env varchar(256), last_comm datetime(3)," +
		" node_frozen varchar(1), model varchar(256), os_name varchar(32), os_vendor varchar(32), os_release varchar(32), os_update varchar(32)," +
		" os_concat varchar(140) GENERATED ALWAYS AS (concat_ws(' ', os_name, os_vendor, os_release, os_update)) VIRTUAL)",
	"CREATE TABLE services (svc_id char(36) CHARACTER SET ascii PRIMARY KEY, svc_env varchar(10))",
	"CREATE TABLE svcmon (svc_id char(36) CHARACTER SET ascii, node_id char(36) CHARACTER SET ascii, mon_frozen int, mon_updated datetime)",
	"CREATE TABLE comp_status (id int AUTO_INCREMENT PRIMARY KEY, run_module varchar(64) NOT NULL, run_status int NOT NULL DEFAULT 1," +
		" node_id char(36) CHARACTER SET ascii DEFAULT '', svc_id char(36) CHARACTER SET ascii DEFAULT '')",
	"CREATE TABLE node_users (id int AUTO_INCREMENT PRIMARY KEY, user_name varchar(255) NOT NULL, user_id bigint, node_id char(36) CHARACTER SET ascii DEFAULT '')",
	"CREATE TABLE node_groups (id int AUTO_INCREMENT PRIMARY KEY, group_name varchar(255) NOT NULL, group_id bigint, node_id char(36) CHARACTER SET ascii DEFAULT '')",
	"CREATE TABLE obsolescence (id int AUTO_INCREMENT PRIMARY KEY, obs_type varchar(30) NOT NULL, obs_name varchar(100) NOT NULL," +
		" obs_warn_date datetime, obs_alert_date datetime) DEFAULT CHARSET=latin1",
}

type testAlert struct {
	Type, SvcID, NodeID, Instance, Dict, Env string
	Severity                                 int
}

func testAlerts(t *testing.T, db *sql.DB) []testAlert {
	t.Helper()
	rows, err := db.Query("SELECT dash_type, IFNULL(svc_id, ''), IFNULL(node_id, ''), IFNULL(dash_instance, ''), IFNULL(dash_dict, ''), IFNULL(dash_env, ''), dash_severity" +
		" FROM dashboard ORDER BY dash_type, svc_id, node_id, dash_instance")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var l []testAlert
	for rows.Next() {
		var a testAlert
		if err := rows.Scan(&a.Type, &a.SvcID, &a.NodeID, &a.Instance, &a.Dict, &a.Env, &a.Severity); err != nil {
			t.Fatal(err)
		}
		l = append(l, a)
	}
	return l
}

func testExec(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	for _, s := range statements {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %s", s, err)
		}
	}
}

func testDashboardDB(db *sql.DB) *DB {
	odb := New(db)
	odb.Metrics = testMetrics()
	odb.Session = NewSession(db, nil)
	return odb
}

func TestDashboardUpdateFrozen(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	testExec(t, db,
		"INSERT INTO nodes (node_id, node_env, node_frozen) VALUES ('n1', 'PRD', 'T'), ('n2', 'DEV', 'F'), ('n3', 'DEV', NULL)",
		"INSERT INTO services VALUES ('s1', 'PRD'), ('s2', 'TST')",
		"INSERT INTO svcmon VALUES ('s1', 'n1', 1, NOW()), ('s1', 'n2', 0, NOW()), ('s2', 'n2', 1, NOW())",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	if err := odb.DashboardUpdateFrozen(ctx); err != nil {
		t.Fatal(err)
	}
	want := []testAlert{
		{Type: "node frozen", NodeID: "n1", Env: "PRD", Severity: 1},
		{Type: "service frozen", SvcID: "s1", NodeID: "n1", Env: "PRD", Severity: 1},
		{Type: "service frozen", SvcID: "s2", NodeID: "n2", Env: "TST", Severity: 1},
	}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// A run with nothing new changes no row.
	odb.Session = NewSession(db, nil)
	if err := odb.DashboardUpdateFrozen(ctx); err != nil {
		t.Fatal(err)
	}
	if len(odb.Session.tables) != 0 {
		t.Errorf("changes %v on a run with nothing new", odb.Session.tables)
	}

	testExec(t, db, "UPDATE nodes SET node_frozen = 'F' WHERE node_id = 'n1'", "DELETE FROM svcmon WHERE svc_id = 's2'",
		"UPDATE nodes SET node_frozen = 'T' WHERE node_id = 'n3'")
	if err := odb.DashboardUpdateFrozen(ctx); err != nil {
		t.Fatal(err)
	}
	want = []testAlert{
		{Type: "node frozen", NodeID: "n3", Env: "DEV", Severity: 1},
		{Type: "service frozen", SvcID: "s1", NodeID: "n1", Env: "PRD", Severity: 1},
	}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestDashboardUpdateNodeDuplicateIDs(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	testExec(t, db,
		"INSERT INTO nodes (node_id, node_env) VALUES ('n1', 'PRD'), ('n2', 'DEV')",
		"INSERT INTO node_users (node_id, user_name, user_id) VALUES ('n1', 'root', 0), ('n1', 'toor', 0), ('n1', 'bob', 1000),"+
			" ('n1', 'b2', 1001), ('n1', 'b1', 1001), ('n1', 'x', NULL), ('n1', 'y', NULL), ('n2', 'a', 5), ('n2', 'b', 5)",
		"INSERT INTO node_groups (node_id, group_name, group_id) VALUES ('n1', 'wheel', 10), ('n1', 'adm', 10)",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	if err := odb.DashboardUpdateNodeDuplicateIDs(ctx, "n1", "uid", now); err != nil {
		t.Fatal(err)
	}
	if err := odb.DashboardUpdateNodeDuplicateIDs(ctx, "n1", "gid", now); err != nil {
		t.Fatal(err)
	}
	want := []testAlert{
		{Type: "duplicate gid", NodeID: "n1", Instance: "10", Dict: `{"gid": 10, "groupnames": "adm,wheel"}`, Env: "PRD", Severity: 1},
		{Type: "duplicate uid", NodeID: "n1", Instance: "0", Dict: `{"uid": 0, "usernames": "root,toor"}`, Env: "PRD", Severity: 1},
		{Type: "duplicate uid", NodeID: "n1", Instance: "1001", Dict: `{"uid": 1001, "usernames": "b1,b2"}`, Env: "PRD", Severity: 1},
	}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// The uid 1001 no longer shared: its alert goes at the next push.
	testExec(t, db, "DELETE FROM node_users WHERE user_name = 'b2'")
	if err := odb.DashboardUpdateNodeDuplicateIDs(ctx, "n1", "uid", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want = slices.Delete(want, 2, 3)
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if err := odb.DashboardUpdateNodeDuplicateIDs(ctx, "n1", "foo", now); err == nil {
		t.Error("kind foo: no error")
	}
}

func TestDashboardUpdateCompDiff(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	testExec(t, db,
		"INSERT INTO nodes (node_id, nodename) VALUES ('n1', 'node1'), ('n2', 'node2'), ('n3', 'node3'), ('n4', 'node4')",
		"INSERT INTO services VALUES ('s1', 'PRD'), ('s2', 'DEV'), ('s3', 'DEV')",
		// s1 on n1, n2, n3 (n3 not seen for 2 days); s2 on n1, n4; s3 on n4 only
		"INSERT INTO svcmon VALUES ('s1', 'n1', 0, NOW()), ('s1', 'n2', 0, NOW()), ('s1', 'n3', 0, NOW() - INTERVAL 2 DAY),"+
			" ('s2', 'n1', 0, NOW()), ('s2', 'n4', 0, NOW()), ('s3', 'n4', 0, NOW())",
		// m1: ok/nok on n1/n2 → difference; m2: ok/n/a → none; m3: all nok → none;
		// m4: ok/nok/n/a → difference on s1's n1, n2, but only ok/n/a on s2's n1, n4;
		// m5 differs only with n3, too old.
		"INSERT INTO comp_status (node_id, svc_id, run_module, run_status) VALUES"+
			" ('n1', '', 'm1', 0), ('n2', '', 'm1', 1),"+
			" ('n1', '', 'm2', 0), ('n2', '', 'm2', 2),"+
			" ('n1', '', 'm3', 1), ('n2', NULL, 'm3', 1),"+
			" ('n1', '', 'm4', 0), ('n2', '', 'm4', 1), ('n4', '', 'm4', 2),"+
			" ('n1', '', 'm5', 0), ('n3', '', 'm5', 1),"+
			// a service module status is not a node one
			" ('n1', 's1', 'm6', 0), ('n2', 's1', 'm6', 1)",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	if err := odb.DashboardUpdateCompDiff(ctx); err != nil {
		t.Fatal(err)
	}
	want := []testAlert{
		{Type: "compliance differences in cluster", SvcID: "s1", Dict: `{"n":2,"nodes":"node1,node2"}`, Env: "PRD", Severity: 1},
	}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// n3 pings again: its instance, not updated by a status for 2 days, is
	// seen, and m5 differs.
	testExec(t, db, "UPDATE nodes SET last_comm = NOW() WHERE node_id = 'n3'")
	if err := odb.DashboardUpdateCompDiff(ctx); err != nil {
		t.Fatal(err)
	}
	want[0].Dict = `{"n":3,"nodes":"node1,node2,node3"}`
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("n3 pinging: got %+v\nwant %+v", got, want)
	}

	// The purge deletes the alerts written before the run, to the second.
	testExec(t, db, "UPDATE comp_status SET run_status = 0",
		"UPDATE dashboard SET dash_updated = dash_updated - INTERVAL 1 MINUTE")
	if err := odb.DashboardUpdateCompDiff(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testAlerts(t, db); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestPurgeAlertsObsWithout(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	testExec(t, db,
		"INSERT INTO nodes (node_id, node_env, model, os_name, os_vendor, os_release, os_update) VALUES"+
			" ('n1', 'PRD', 'm-a', 'Linux', 'Ubuntu', '24.04', 'u1'), ('n2', 'DEV', 'VMware Virtual Platform', 'Linux', 'Ubuntu', '24.04', 'u1')",
		"INSERT INTO obsolescence (obs_type, obs_name, obs_warn_date, obs_alert_date) VALUES"+
			" ('hw', 'm-a', '2030-01-01', NULL), ('hw', 'VMware Virtual Platform', NULL, NULL), ('os', 'Linux Ubuntu 24.04 u1', NULL, NULL)",
		// a stale alert for a model the node no longer has
		"INSERT INTO dashboard (dash_type, node_id, dash_severity, dash_dict, dash_updated) VALUES"+
			" ('hardware obsolescence warning date not set', 'n1', 0, '{\"o\": \"m-old\"}', NOW() - INTERVAL 1 DAY)",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	if err := odb.PurgeAlertsObsWithout(ctx); err != nil {
		t.Fatal(err)
	}
	want := []testAlert{
		{Type: "hardware obsolescence alert date not set", NodeID: "n1", Dict: `{"o": "m-a"}`, Env: "PRD"},
		{Type: "os obsolescence alert date not set", NodeID: "n1", Dict: `{"o": "Linux Ubuntu 24.04 u1"}`, Env: "PRD"},
		{Type: "os obsolescence alert date not set", NodeID: "n2", Dict: `{"o": "Linux Ubuntu 24.04 u1"}`, Env: "DEV"},
		{Type: "os obsolescence warning date not set", NodeID: "n1", Dict: `{"o": "Linux Ubuntu 24.04 u1"}`, Env: "PRD"},
		{Type: "os obsolescence warning date not set", NodeID: "n2", Dict: `{"o": "Linux Ubuntu 24.04 u1"}`, Env: "DEV"},
	}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// The alert setting given to the os removes its alerts, and
	// DeleteDashObsWithout matches the dict written.
	if err := odb.DeleteDashObsWithout(ctx, "Linux Ubuntu 24.04 u1", "os", "warn"); err != nil {
		t.Fatal(err)
	}
	// The purge deletes the alerts written before the run, to the second: the
	// task runs hourly, the test in the same second.
	testExec(t, db, "UPDATE obsolescence SET obs_alert_date = '2035-01-01', obs_warn_date = '2030-01-01' WHERE obs_type = 'os'",
		"UPDATE dashboard SET dash_updated = dash_updated - INTERVAL 1 MINUTE")
	if err := odb.PurgeAlertsObsWithout(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testAlerts(t, db); !slices.Equal(got, want[:1]) {
		t.Fatalf("got %+v\nwant %+v", got, want[:1])
	}
}

func TestDashboardUpdateSlowTask(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	odb := testDashboardDB(db)
	ctx := context.Background()
	if err := odb.DashboardUpdateSlowTask(ctx, 3); err != nil {
		t.Fatal(err)
	}
	want := []testAlert{{Type: "slow task", Dict: `{"n": "3"}`, Env: "PRD", Severity: 3}}
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// still slow: the alert is updated, not duplicated
	if err := odb.DashboardUpdateSlowTask(ctx, 5); err != nil {
		t.Fatal(err)
	}
	want[0].Dict = `{"n": "5"}`
	if got := testAlerts(t, db); !slices.Equal(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if err := odb.DashboardUpdateSlowTask(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if got := testAlerts(t, db); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
