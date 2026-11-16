package serverhandlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
	"github.com/shaj13/go-guardian/v2/auth"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/xauth"
)

func TestPrefixUsableRange(t *testing.T) {
	for _, tc := range []struct{ prefix, begin, end string }{
		{"10.0.0.0/24", "10.0.0.1", "10.0.0.254"},
		{"10.0.0.0/30", "10.0.0.1", "10.0.0.2"},
		{"10.0.0.0/31", "10.0.0.0", "10.0.0.1"},
		{"10.0.0.7/32", "10.0.0.7", "10.0.0.7"},
		{"0.0.0.0/0", "0.0.0.1", "255.255.255.254"},
	} {
		begin, end := prefixUsableRange(netip.MustParsePrefix(tc.prefix))
		if begin.String() != tc.begin || end.String() != tc.end {
			t.Errorf("%s: %s - %s, want %s - %s", tc.prefix, begin, end, tc.begin, tc.end)
		}
	}
}

// networksTestAPI is an Api on a new MariaDB database holding the network
// tables: network 1 10.0.0.0/24 of team Net with segment 1 10.0.0.10-10.0.0.19
// (group Seg responsible) and segment 2 10.0.0.20-10.0.0.29; network 2
// 10.1.0.0/29 without segment; node n1 reporting 10.0.0.11 and 10.1.0.2. User
// 1 is a member of Seg, user 2 of Other.
func networksTestAPI(t *testing.T) (*Api, *sql.DB) {
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
	name := fmt.Sprintf("oc3_test_networks_%d", time.Now().UnixNano())
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
		"CREATE TABLE auth_membership (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, group_id INT, primary_group CHAR(1) DEFAULT 'F')",
		"CREATE TABLE log (id INT AUTO_INCREMENT PRIMARY KEY, log_action VARCHAR(100) NOT NULL, log_user VARCHAR(100) NOT NULL," +
			" log_impersonator VARCHAR(100), log_origin VARCHAR(16), log_request_id VARCHAR(64), log_fmt VARCHAR(200), log_dict TEXT, log_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP," +
			" svc_id CHAR(36) DEFAULT '', log_level ENUM('debug','info','warning','error','critical') DEFAULT 'info', node_id CHAR(36) DEFAULT '')",
		"CREATE TABLE networks (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), network VARCHAR(40), netmask SMALLINT UNSIGNED," +
			" team_responsible VARCHAR(255), comment TEXT, pvid INT, gateway VARCHAR(40)," +
			" begin VARCHAR(16) GENERATED ALWAYS AS (INET_NTOA(INET_ATON(network) + 1)) STORED," +
			" updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, prio INT NOT NULL DEFAULT 0," +
			" end VARCHAR(16) GENERATED ALWAYS AS (INET_NTOA(INET_ATON(network) + POW(2, 32 - netmask) - 2)) VIRTUAL," +
			" broadcast VARCHAR(16) GENERATED ALWAYS AS (INET_NTOA(INET_ATON(network) + POW(2, 32 - netmask) - 1)) VIRTUAL," +
			" UNIQUE KEY idx1 (name), UNIQUE KEY idx2 (network, netmask))",
		"CREATE TABLE network_segments (id INT AUTO_INCREMENT PRIMARY KEY, net_id INT, seg_type ENUM('dynamic','static') DEFAULT 'static', seg_begin VARCHAR(40), seg_end VARCHAR(40))",
		"CREATE TABLE network_segment_responsibles (id INT AUTO_INCREMENT PRIMARY KEY, seg_id INT, group_id INT)",
		"CREATE TABLE nodes (node_id CHAR(36) PRIMARY KEY, nodename VARCHAR(255))",
		"CREATE TABLE node_ip (id INT AUTO_INCREMENT PRIMARY KEY, node_id CHAR(36), addr VARCHAR(45))",
		"INSERT INTO auth_group (id, role, privilege) VALUES (1, 'Net', 'F'), (2, 'Seg', 'F'), (3, 'Other', 'F'), (4, 'Manager', 'T')",
		"INSERT INTO auth_membership (user_id, group_id) VALUES (1, 2), (2, 3)",
		"INSERT INTO networks (id, name, network, netmask, team_responsible) VALUES (1, 'lan', '10.0.0.0', 24, 'Net'), (2, 'small', '10.1.0.0', 29, 'Net')",
		"INSERT INTO network_segments (id, net_id, seg_type, seg_begin, seg_end) VALUES (1, 1, 'static', '10.0.0.10', '10.0.0.19'), (2, 1, 'dynamic', '10.0.0.20', '10.0.0.29')",
		"INSERT INTO network_segment_responsibles (seg_id, group_id) VALUES (1, 2)",
		"INSERT INTO nodes VALUES ('n1', 'node1')",
		"INSERT INTO node_ip (node_id, addr) VALUES ('n1', '10.0.0.11'), ('n1', '10.1.0.2')",
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

// networksContext is a request of user 1 in the groups.
func networksContext(method, body string, groups ...string) (echo.Context, *httptest.ResponseRecorder) {
	return networksContextAs("1", method, body, groups...)
}

func networksContextAs(userID, method, body string, groups ...string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if body != "" {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	ext := make(auth.Extensions)
	ext.Set(xauth.XUserID, userID)
	c.Set("user", auth.NewUserInfo("u@example.com", userID, nil, ext))
	c.Set(XAuthMode, AuthModeUser)
	c.Set(XUserEmail, "u@example.com")
	c.Set("groups", groups)
	return c, rec
}

func expectCode(t *testing.T, what string, err error, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	// A refusal writes its problem response and returns an error, as
	// denyRequest.
	if err != nil && (rec.Code != code || code < 400) {
		t.Fatalf("%s: %v", what, err)
	}
	if rec.Code != code {
		t.Fatalf("%s: %d %s, want %d", what, rec.Code, rec.Body.String(), code)
	}
}

func queryString(t *testing.T, pool *sql.DB, query string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := pool.QueryRow(query, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return s.String
}

func TestPostNetwork(t *testing.T) {
	a, pool := networksTestAPI(t)

	c, rec := networksContext(http.MethodPost, `{"name":"lan2"}`, "NetworkManager", "Other")
	expectCode(t, "not responsible", a.PostNetwork(c, "1"), rec, http.StatusForbidden)

	c, rec = networksContext(http.MethodPost, `{"name":"lan2"}`, "Net")
	expectCode(t, "no NetworkManager", a.PostNetwork(c, "1"), rec, http.StatusForbidden)

	c, rec = networksContext(http.MethodPost, `{"name":"lan2","gateway":"10.0.0.254","prio":3,"comment":"c"}`, "NetworkManager", "Net")
	expectCode(t, "update", a.PostNetwork(c, "1"), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT CONCAT_WS(',', name, gateway, prio, comment) FROM networks WHERE id = 1"); got != "lan2,10.0.0.254,3,c" {
		t.Errorf("network 1: %s", got)
	}

	c, rec = networksContext(http.MethodPost, `{"name":"small"}`, "NetworkManager", "Net")
	expectCode(t, "name taken", a.PostNetwork(c, "1"), rec, http.StatusConflict)

	c, rec = networksContext(http.MethodPost, `{"network":"10.0.0.0","netmask":28}`, "NetworkManager", "Net")
	expectCode(t, "segments outside", a.PostNetwork(c, "1"), rec, http.StatusConflict)

	c, rec = networksContext(http.MethodPost, `{"network":"10.0.0.1"}`, "NetworkManager", "Net")
	expectCode(t, "not a network address", a.PostNetwork(c, "1"), rec, http.StatusBadRequest)

	c, rec = networksContext(http.MethodPost, `{"gateway":"10.9.0.1"}`, "NetworkManager", "Net")
	expectCode(t, "gateway outside", a.PostNetwork(c, "1"), rec, http.StatusBadRequest)

	c, rec = networksContext(http.MethodPost, `{"netmask":23}`, "NetworkManager", "Manager")
	expectCode(t, "manager widens", a.PostNetwork(c, "1"), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT CONCAT(network, '/', netmask, ' ', end) FROM networks WHERE id = 1"); got != "10.0.0.0/23 10.0.1.254" {
		t.Errorf("network 1: %s", got)
	}
	if got := queryString(t, pool, "SELECT COUNT(*) FROM log WHERE log_action = 'networks.update'"); got != "2" {
		t.Errorf("%s update logs, want 2", got)
	}
}

func TestDeleteNetwork(t *testing.T) {
	a, pool := networksTestAPI(t)
	c, rec := networksContext(http.MethodDelete, "", "NetworkManager", "Net")
	expectCode(t, "delete", a.DeleteNetwork(c, "1"), rec, http.StatusOK)
	got := queryString(t, pool, "SELECT CONCAT((SELECT COUNT(*) FROM networks), (SELECT COUNT(*) FROM network_segments), (SELECT COUNT(*) FROM network_segment_responsibles))")
	if got != "100" {
		t.Errorf("networks, segments, responsibles left: %s, want 100", got)
	}
	c, rec = networksContext(http.MethodDelete, "", "NetworkManager", "Net")
	expectCode(t, "delete again", a.DeleteNetwork(c, "1"), rec, http.StatusNotFound)
}

func TestNetworkSegments(t *testing.T) {
	a, pool := networksTestAPI(t)

	c, rec := networksContext(http.MethodGet, "")
	expectCode(t, "list", a.GetNetworkSegments(c, "1", server.GetNetworkSegmentsParams{}), rec, http.StatusOK)
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 2 || list.Data[0]["seg_begin"] != "10.0.0.10" {
		t.Fatalf("segments: %s %v", rec.Body.String(), err)
	}

	// user 1, member of Seg responsible for segment 1, not of the network team
	c, rec = networksContext(http.MethodPost, `{"seg_end":"10.0.0.15"}`, "NetworkManager", "Seg")
	expectCode(t, "segment responsible", a.PostNetworkSegment(c, "1", "1"), rec, http.StatusOK)
	c, rec = networksContext(http.MethodPost, `{"seg_end":"10.0.0.25"}`, "NetworkManager", "Seg")
	expectCode(t, "not responsible for segment 2", a.PostNetworkSegment(c, "1", "2"), rec, http.StatusForbidden)
	c, rec = networksContext(http.MethodPost, `{"seg_end":"10.0.0.21"}`, "NetworkManager", "Seg")
	expectCode(t, "overlap", a.PostNetworkSegment(c, "1", "1"), rec, http.StatusConflict)
	c, rec = networksContext(http.MethodPost, `{"seg_end":"10.0.1.1"}`, "NetworkManager", "Net")
	expectCode(t, "outside", a.PostNetworkSegment(c, "1", "2"), rec, http.StatusBadRequest)
	c, rec = networksContext(http.MethodPost, `{"seg_type":"dynamic"}`, "NetworkManager", "Net")
	expectCode(t, "network team", a.PostNetworkSegment(c, "1", "1"), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT CONCAT_WS(' ', seg_type, seg_begin, seg_end) FROM network_segments WHERE id = 1"); got != "dynamic 10.0.0.10 10.0.0.15" {
		t.Errorf("segment 1: %s", got)
	}
	c, rec = networksContext(http.MethodPost, `{}`, "NetworkManager", "Net")
	expectCode(t, "segment of another network", a.PostNetworkSegment(c, "2", "1"), rec, http.StatusNotFound)

	// deleting takes the network team, as the historical collector
	c, rec = networksContext(http.MethodDelete, "", "NetworkManager", "Seg")
	expectCode(t, "delete by segment responsible", a.DeleteNetworkSegment(c, "1", "1"), rec, http.StatusForbidden)
	c, rec = networksContext(http.MethodDelete, "", "NetworkManager", "Net")
	expectCode(t, "delete", a.DeleteNetworkSegment(c, "1", "1"), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT CONCAT((SELECT COUNT(*) FROM network_segments), (SELECT COUNT(*) FROM network_segment_responsibles))"); got != "10" {
		t.Errorf("segments, responsibles left: %s, want 10", got)
	}
}

func TestNetworkSegmentResponsibles(t *testing.T) {
	a, pool := networksTestAPI(t)

	c, rec := networksContext(http.MethodPost, "", "Seg")
	expectCode(t, "attach", a.PostNetworkSegmentResponsible(c, "1", "1", "Other"), rec, http.StatusOK)
	c, rec = networksContext(http.MethodPost, "", "Seg")
	expectCode(t, "attach again", a.PostNetworkSegmentResponsible(c, "1", "1", "3"), rec, http.StatusConflict)
	c, rec = networksContext(http.MethodPost, "", "Seg")
	expectCode(t, "privilege", a.PostNetworkSegmentResponsible(c, "1", "1", "Manager"), rec, http.StatusBadRequest)
	c, rec = networksContext(http.MethodPost, "", "Seg")
	expectCode(t, "unknown group", a.PostNetworkSegmentResponsible(c, "1", "1", "nope"), rec, http.StatusNotFound)
	c, rec = networksContextAs("2", http.MethodPost, "", "Other")
	expectCode(t, "not responsible", a.PostNetworkSegmentResponsible(c, "1", "2", "Other"), rec, http.StatusForbidden)

	c, rec = networksContext(http.MethodGet, "")
	expectCode(t, "list", a.GetNetworkSegmentResponsibles(c, "1", "1", server.GetNetworkSegmentResponsiblesParams{}), rec, http.StatusOK)
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 2 || list.Data[0]["role"] != "Other" || list.Data[1]["role"] != "Seg" {
		t.Fatalf("responsibles: %s %v", rec.Body.String(), err)
	}

	c, rec = networksContext(http.MethodDelete, "", "Seg")
	expectCode(t, "detach", a.DeleteNetworkSegmentResponsible(c, "1", "1", "Other"), rec, http.StatusOK)
	c, rec = networksContext(http.MethodDelete, "", "Seg")
	expectCode(t, "detach again", a.DeleteNetworkSegmentResponsible(c, "1", "1", "Other"), rec, http.StatusNotFound)
	if got := queryString(t, pool, "SELECT GROUP_CONCAT(log_action ORDER BY id) FROM log"); got != "networks.segment.attach,networks.segment.detach" {
		t.Errorf("logs: %s", got)
	}
}

func TestGetNetworkIps(t *testing.T) {
	a, _ := networksTestAPI(t)
	ips := func(c echo.Context, rec *httptest.ResponseRecorder, netID string, params server.GetNetworkIpsParams) (int, []server.NetworkIpRow) {
		t.Helper()
		expectCode(t, "ips "+netID, a.GetNetworkIps(c, netID, params), rec, http.StatusOK)
		var list struct {
			Data []server.NetworkIpRow `json:"data"`
			Meta struct {
				Count int `json:"count"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		return list.Meta.Count, list.Data
	}

	// no segment: the whole network
	c, rec := networksContext(http.MethodGet, "", "Other")
	count, data := ips(c, rec, "2", server.GetNetworkIpsParams{})
	if count != 6 || len(data) != 6 || data[0].Ip != "10.1.0.1" || data[5].Ip != "10.1.0.6" || len(data[1].Nodes) != 1 || data[1].Nodes[0].Nodename != "node1" {
		t.Errorf("network 2: %d %+v", count, data)
	}
	free := true
	c, rec = networksContext(http.MethodGet, "", "Other")
	if count, _ = ips(c, rec, "2", server.GetNetworkIpsParams{Free: &free}); count != 5 {
		t.Errorf("network 2 free: %d, want 5", count)
	}

	// segments: those of the user's groups, all for a manager
	c, rec = networksContext(http.MethodGet, "", "Seg")
	count, data = ips(c, rec, "1", server.GetNetworkIpsParams{})
	if count != 10 || data[0].SegId == nil || *data[0].SegId != 1 || data[1].Ip != "10.0.0.11" || len(data[1].Nodes) != 1 {
		t.Errorf("network 1 for Seg: %d %+v", count, data)
	}
	limit, offset := 2, 9
	c, rec = networksContext(http.MethodGet, "", "Manager")
	count, data = ips(c, rec, "1", server.GetNetworkIpsParams{Limit: &limit, Offset: &offset})
	if count != 20 || len(data) != 2 || data[0].Ip != "10.0.0.19" || data[1].Ip != "10.0.0.20" || *data[1].SegType != "dynamic" {
		t.Errorf("network 1 for a manager: %d %+v", count, data)
	}

	// the team responsible for the network sees every segment
	c, rec = networksContextAs("2", http.MethodGet, "", "Net")
	if count, _ = ips(c, rec, "1", server.GetNetworkIpsParams{}); count != 20 {
		t.Errorf("network 1 for its team: %d, want 20", count)
	}

	c, rec = networksContextAs("2", http.MethodGet, "", "Other")
	expectCode(t, "no segment of the user", a.GetNetworkIps(c, "1", server.GetNetworkIpsParams{}), rec, http.StatusForbidden)
}
