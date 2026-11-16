package serverhandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
)

// TestCheckSysrepPattern checks the patterns are validated by the regular
// expression engine of the sysreport access checks.
func TestCheckSysrepPattern(t *testing.T) {
	s := func(v string) *string { return &v }
	for _, tc := range []struct {
		pattern *string
		ok      bool
	}{
		{nil, false},
		{s(""), false},
		{s("  "), false},
		{s(".*/etc/passwd"), true},
		{s("/etc/(shadow|gshadow)"), true},
		{s("/etc/[a-"), false},
		// RE2 has no lookahead: the access checks could not use it.
		{s("/etc/(?!hosts)"), false},
		{s(strings.Repeat("a", sysrepPatternMaxLen+1)), false},
	} {
		_, err := checkSysrepPattern(tc.pattern)
		if (err == nil) != tc.ok {
			name := "<nil>"
			if tc.pattern != nil {
				name = *tc.pattern
				if len(name) > 20 {
					name = name[:20] + "..."
				}
			}
			t.Errorf("%q: %v, want ok %v", name, err, tc.ok)
		}
	}
}

// sysrepTestAPI is an Api on a new database of the MariaDB server
// OC3_TEST_MYSQL_DSN names, holding the tables of the sysreport access rules
// and those they need, dropped at the end of the test.
func sysrepTestAPI(t *testing.T) (*Api, *sql.DB) {
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
	cfg.InterpolateParams = true
	cfg.DBName = ""
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("oc3_test_sysrep_%d", time.Now().UnixNano())
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
	for _, s := range []string{
		"CREATE TABLE auth_group (id INT AUTO_INCREMENT PRIMARY KEY, role VARCHAR(255) NOT NULL, description LONGTEXT, privilege CHAR(1) DEFAULT 'F')",
		"CREATE TABLE gen_filtersets (id INT AUTO_INCREMENT PRIMARY KEY, fset_name VARCHAR(30) NOT NULL, fset_stats VARCHAR(1) DEFAULT 'F')",
		"CREATE TABLE log (id INT AUTO_INCREMENT PRIMARY KEY, log_action VARCHAR(100) NOT NULL, log_user VARCHAR(100) NOT NULL," +
			" log_impersonator VARCHAR(100), log_origin VARCHAR(16), log_request_id VARCHAR(64), log_fmt VARCHAR(200), log_dict TEXT, log_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP," +
			" svc_id CHAR(36) DEFAULT '', log_level ENUM('debug','info','warning','error','critical') DEFAULT 'info', node_id CHAR(36) DEFAULT '')",
		// As in the collector.
		"CREATE TABLE sysrep_secure (id INT(11) NOT NULL AUTO_INCREMENT, pattern TEXT NOT NULL, PRIMARY KEY (id))",
		"CREATE TABLE sysrep_allow (id INT(11) NOT NULL AUTO_INCREMENT, pattern TEXT NOT NULL, fset_id INT(11) NOT NULL, group_id INT(11) NOT NULL, PRIMARY KEY (id))",
		"INSERT INTO auth_group (id, role, privilege) VALUES (1, 'Manager', 'T'), (2, 'Ops', 'F'), (3, 'Dba', 'F')",
		"INSERT INTO gen_filtersets (id, fset_name) VALUES (10, 'linux'), (11, 'prod')",
	} {
		if _, err := pool.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	initMetrics.Do(cdb.InitMetrics)
	odb := cdb.New(pool)
	odb.CreateSession(noEvents{})
	return &Api{ODB: odb, SyncTimeout: 10 * time.Second}, pool
}

// sysrepRows are the data of a list answer.
func sysrepRows(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return list.Data
}

// TestSysreportAccessRules creates, lists, reads and deletes secure patterns
// and authorizations, on a MariaDB: the writes require a Manager, the reads a
// user; a duplicate is a conflict, an invalid regular expression or an
// unknown group or filterset refused; each write is logged; the access checks
// of the sysreport read what was written.
func TestSysreportAccessRules(t *testing.T) {
	a, pool := sysrepTestAPI(t)
	manager := []string{"Manager"}
	ops := []string{"Ops"}
	call := func(groups []string, method, target, body string, h func(echo.Context) error) *httptest.ResponseRecorder {
		t.Helper()
		c, rec := aiContext(method, target, body, groups...)
		_ = h(c)
		return rec
	}
	expect := func(rec *httptest.ResponseRecorder, code int, what string) {
		t.Helper()
		if rec.Code != code {
			t.Fatalf("%s: %d %s, want %d", what, rec.Code, rec.Body.String(), code)
		}
	}
	postPattern := func(groups []string, body string) *httptest.ResponseRecorder {
		return call(groups, http.MethodPost, "/sysreport/secure_patterns", body, a.PostSysreportSecurePatterns)
	}
	postAllow := func(groups []string, body string) *httptest.ResponseRecorder {
		return call(groups, http.MethodPost, "/sysreport/authorizations", body, a.PostSysreportAuthorizations)
	}

	// Secure patterns.
	rec := postPattern(manager, `{"pattern":".*/etc/shadow"}`)
	expect(rec, http.StatusOK, "create a secure pattern")
	rows := sysrepRows(t, rec)
	if len(rows) != 1 || rows[0]["pattern"] != ".*/etc/shadow" {
		t.Fatalf("created %v", rows)
	}
	shadowID := int(rows[0]["id"].(float64))
	expect(postPattern(manager, `{"pattern":".*/etc/shadow"}`), http.StatusConflict, "create it again")
	expect(postPattern(manager, `{"pattern":".*/etc/SHADOW"}`), http.StatusOK, "create a pattern differing by case")
	expect(postPattern(manager, `{"pattern":"/etc/(?!hosts)"}`), http.StatusBadRequest, "create a lookahead")
	expect(postPattern(manager, `{}`), http.StatusBadRequest, "create no pattern")
	expect(postPattern(ops, `{"pattern":"/root/.*"}`), http.StatusForbidden, "create as Ops")

	c, rec := aiContext(http.MethodGet, "/sysreport/secure_patterns", "", ops...)
	_ = a.GetSysreportSecurePatterns(c, server.GetSysreportSecurePatternsParams{})
	expect(rec, http.StatusOK, "list as Ops")
	if rows := sysrepRows(t, rec); len(rows) != 2 {
		t.Errorf("list %v", rows)
	}
	c, rec = aiContext(http.MethodGet, "/sysreport/secure_patterns", "")
	c.Set(XAuthMode, AuthModeNode)
	_ = a.GetSysreportSecurePatterns(c, server.GetSysreportSecurePatternsParams{})
	expect(rec, http.StatusUnauthorized, "list as a node")
	expect(call(ops, http.MethodGet, "/sysreport/secure_patterns/999", "", func(c echo.Context) error {
		return a.GetSysreportSecurePattern(c, 999, server.GetSysreportSecurePatternParams{})
	}), http.StatusNotFound, "read a missing pattern")

	patterns, err := a.ODB.SysrepSecurePatterns(context.Background())
	if err != nil || len(patterns) != 2 {
		t.Errorf("the access checks read %v, %v", patterns, err)
	}

	deletePattern := func(groups []string, id int) *httptest.ResponseRecorder {
		return call(groups, http.MethodDelete, fmt.Sprintf("/sysreport/secure_patterns/%d", id), "", func(c echo.Context) error {
			return a.DeleteSysreportSecurePattern(c, id)
		})
	}
	expect(deletePattern(ops, shadowID), http.StatusForbidden, "delete as Ops")
	expect(deletePattern(manager, shadowID), http.StatusOK, "delete")
	expect(deletePattern(manager, shadowID), http.StatusNotFound, "delete again")

	// Authorizations.
	rec = postAllow(manager, `{"group_name":"Ops","fset_id":10,"pattern":"/etc/.*"}`)
	expect(rec, http.StatusOK, "create an authorization")
	rows = sysrepRows(t, rec)
	if len(rows) != 1 || rows[0]["group_name"] != "Ops" || rows[0]["fset_name"] != "linux" || rows[0]["pattern"] != "/etc/.*" {
		t.Fatalf("created %v", rows)
	}
	allowID := int(rows[0]["id"].(float64))
	expect(postAllow(manager, `{"group_id":2,"fset_name":"linux","pattern":"/etc/.*"}`), http.StatusConflict, "create it again by ids")
	expect(postAllow(manager, `{"group_id":3,"fset_name":"prod","pattern":"/var/lib/.*"}`), http.StatusOK, "create another")
	expect(postAllow(manager, `{"group_name":"Nobody","fset_id":10,"pattern":".*"}`), http.StatusNotFound, "unknown group")
	expect(postAllow(manager, `{"group_id":99,"fset_id":10,"pattern":".*"}`), http.StatusNotFound, "unknown group id")
	expect(postAllow(manager, `{"group_id":2,"fset_name":"none","pattern":".*"}`), http.StatusNotFound, "unknown filterset")
	expect(postAllow(manager, `{"group_id":2,"fset_id":99,"pattern":".*"}`), http.StatusNotFound, "unknown filterset id")
	expect(postAllow(manager, `{"fset_id":10,"pattern":".*"}`), http.StatusBadRequest, "no group")
	expect(postAllow(manager, `{"group_id":2,"pattern":".*"}`), http.StatusBadRequest, "no filterset")
	expect(postAllow(manager, `{"group_id":2,"group_name":"Ops","fset_id":10,"pattern":".*"}`), http.StatusBadRequest, "group by id and name")
	expect(postAllow(manager, `{"group_id":2,"fset_id":10,"pattern":"("}`), http.StatusBadRequest, "invalid pattern")
	expect(postAllow(ops, `{"group_id":2,"fset_id":10,"pattern":".*"}`), http.StatusForbidden, "create as Ops")

	c, rec = aiContext(http.MethodGet, "/sysreport/authorizations", "", ops...)
	filter := server.InQueryFilter{"group_name:eq:Dba"}
	_ = a.GetSysreportAuthorizations(c, server.GetSysreportAuthorizationsParams{Filter: &filter})
	expect(rec, http.StatusOK, "list as Ops")
	if rows := sysrepRows(t, rec); len(rows) != 1 || rows[0]["fset_name"] != "prod" {
		t.Errorf("filtered list %v", rows)
	}
	rec = call(ops, http.MethodGet, "/sysreport/authorizations", "", func(c echo.Context) error {
		return a.GetSysreportAuthorization(c, allowID, server.GetSysreportAuthorizationParams{})
	})
	expect(rec, http.StatusOK, "read")
	if rows := sysrepRows(t, rec); len(rows) != 1 || rows[0]["group_id"] != float64(2) || rows[0]["fset_id"] != float64(10) {
		t.Errorf("read %v", rows)
	}

	allows, err := a.ODB.SysrepAllows(context.Background(), []int64{2})
	if err != nil || len(allows) != 1 || allows[0].FsetID != 10 || allows[0].Pattern != "/etc/.*" {
		t.Errorf("the access checks read %v, %v", allows, err)
	}

	deleteAllow := func(groups []string, id int) *httptest.ResponseRecorder {
		return call(groups, http.MethodDelete, fmt.Sprintf("/sysreport/authorizations/%d", id), "", func(c echo.Context) error {
			return a.DeleteSysreportAuthorization(c, id)
		})
	}
	expect(deleteAllow(ops, allowID), http.StatusForbidden, "delete as Ops")
	expect(deleteAllow(manager, allowID), http.StatusOK, "delete")
	expect(deleteAllow(manager, allowID), http.StatusNotFound, "delete again")

	// Each write is logged.
	logged := map[string]int{}
	var dicts []string
	r, err := pool.Query("SELECT log_action, log_dict FROM log ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for r.Next() {
		var action, dict string
		if err := r.Scan(&action, &dict); err != nil {
			t.Fatal(err)
		}
		logged[action]++
		dicts = append(dicts, dict)
	}
	want := map[string]int{
		"sysreport.secure_pattern.create": 2,
		"sysreport.secure_pattern.delete": 1,
		"sysreport.authorization.create":  2,
		"sysreport.authorization.delete":  1,
	}
	if fmt.Sprint(logged) != fmt.Sprint(want) {
		t.Errorf("logged %v, want %v", logged, want)
	}
	if !strings.Contains(strings.Join(dicts, "\n"), `"Ops-linux-/etc/.*"`) {
		t.Errorf("log dicts %v", dicts)
	}
}
