package serverhandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/xauth"
)

const testIssuer = "http://127.0.0.1:1/application/o/oc3/"

// identitiesTestAPI is an Api on a new MariaDB database holding the accounts:
// 1 the caller, 2 a service account, 3 a Manager whose identity "m" is linked.
// Its provider has the issuer testIssuer and is never reached.
func identitiesTestAPI(t *testing.T) (*Api, *sql.DB) {
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
	name := fmt.Sprintf("oc3_test_identities_%d", time.Now().UnixNano())
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
		"CREATE TABLE auth_user (id INT AUTO_INCREMENT PRIMARY KEY, first_name VARCHAR(128), last_name VARCHAR(128), email VARCHAR(512), username VARCHAR(128), registration_key VARCHAR(512))",
		"CREATE TABLE auth_group (id INT AUTO_INCREMENT PRIMARY KEY, role VARCHAR(255) NOT NULL, description LONGTEXT, privilege CHAR(1) DEFAULT 'F')",
		"CREATE TABLE auth_membership (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, group_id INT, primary_group CHAR(1) DEFAULT 'F')",
		"CREATE TABLE auth_user_identities (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, issuer VARCHAR(255) NOT NULL, subject VARCHAR(255) NOT NULL," +
			" created DATETIME NOT NULL, last_login DATETIME, UNIQUE KEY uk_identity (issuer, subject))",
		"CREATE TABLE log (id INT AUTO_INCREMENT PRIMARY KEY, log_action VARCHAR(100) NOT NULL, log_user VARCHAR(100) NOT NULL," +
			" log_impersonator VARCHAR(100), log_origin VARCHAR(16), log_request_id VARCHAR(64), log_fmt VARCHAR(200), log_dict TEXT, log_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP," +
			" svc_id CHAR(36) DEFAULT '', log_level ENUM('debug','info','warning','error','critical') DEFAULT 'info', node_id CHAR(36) DEFAULT '')",
		"INSERT INTO auth_user (id, email) VALUES (1, 'admin@example.com'), (2, 'robot@example.com'), (3, 'boss@example.com')",
		"INSERT INTO auth_group (id, role, privilege) VALUES (1, 'Manager', 'T'), (2, 'UserManager', 'T')",
		"INSERT INTO auth_membership (user_id, group_id) VALUES (3, 1)",
		"INSERT INTO auth_user_identities (user_id, issuer, subject, created) VALUES (3, '" + testIssuer + "', 'm', NOW())",
	} {
		if _, err := pool.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancel() // the provider is never discovered
	o, err := xauth.NewOIDC(ctx, xauth.OIDCConfig{
		Issuer: testIssuer, ClientID: "oc3", ClientSecret: "secret", RedirectURL: "http://localhost/auth/callback",
	}, nil, pool)
	if err != nil {
		t.Fatal(err)
	}
	initMetrics.Do(cdb.InitMetrics)
	odb := cdb.New(pool)
	odb.CreateSession(noEvents{})
	a := &Api{ODB: odb, SyncTimeout: 10 * time.Second}
	a.OIDC = o
	return a, pool
}

func TestUserIdentities(t *testing.T) {
	a, pool := identitiesTestAPI(t)

	c, rec := networksContext(http.MethodPost, `{"subject":"robot"}`, "Ops")
	expectCode(t, "no UserManager", a.PostUserIdentities(c, "2"), rec, http.StatusForbidden)

	c, rec = networksContext(http.MethodPost, `{"subject":"robot","issuer":"https://other/"}`, "UserManager")
	expectCode(t, "other issuer", a.PostUserIdentities(c, "2"), rec, http.StatusBadRequest)

	c, rec = networksContext(http.MethodPost, `{"subject":" "}`, "UserManager")
	expectCode(t, "no subject", a.PostUserIdentities(c, "2"), rec, http.StatusBadRequest)

	c, rec = networksContext(http.MethodPost, `{"subject":"robot"}`, "UserManager")
	expectCode(t, "link", a.PostUserIdentities(c, "2"), rec, http.StatusOK)
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 1 ||
		list.Data[0]["subject"] != "robot" || list.Data[0]["issuer"] != testIssuer {
		t.Fatalf("linked: %s %v", rec.Body.String(), err)
	}
	if u, err := a.ODB.UserByIdentity(context.Background(), testIssuer, "robot"); err != nil || u == nil || u.ID != 2 {
		t.Fatalf("identity resolves to %+v, %v, want user 2", u, err)
	}

	c, rec = networksContext(http.MethodPost, `{"subject":"robot"}`, "UserManager")
	expectCode(t, "linked again", a.PostUserIdentities(c, "1"), rec, http.StatusConflict)

	c, rec = networksContext(http.MethodPost, `{"subject":"robot2"}`, "UserManager")
	expectCode(t, "a second identity", a.PostUserIdentities(c, "2"), rec, http.StatusConflict)

	c, rec = networksContext(http.MethodPost, `{"subject":"other"}`, "UserManager")
	expectCode(t, "UserManager on a Manager", a.PostUserIdentities(c, "3"), rec, http.StatusForbidden)
	c, rec = networksContext(http.MethodPost, `{"subject":"other"}`, "Manager")
	expectCode(t, "Manager on a Manager having one", a.PostUserIdentities(c, "boss@example.com"), rec, http.StatusConflict)

	c, rec = networksContext(http.MethodGet, "", "UserManager")
	expectCode(t, "list", a.GetUserIdentities(c, "3", server.GetUserIdentitiesParams{}), rec, http.StatusOK)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Data) != 1 || list.Data[0]["subject"] != "m" {
		t.Fatalf("identities of 3: %s %v", rec.Body.String(), err)
	}
	c, rec = networksContext(http.MethodGet, "", "Ops")
	expectCode(t, "list of another", a.GetUserIdentities(c, "2", server.GetUserIdentitiesParams{}), rec, http.StatusNotFound)
	c, rec = networksContext(http.MethodGet, "", "Ops")
	expectCode(t, "list of self", a.GetUserIdentities(c, "self", server.GetUserIdentitiesParams{}), rec, http.StatusOK)

	id := queryString(t, pool, "SELECT id FROM auth_user_identities WHERE subject = 'robot'")
	c, rec = networksContext(http.MethodDelete, "", "UserManager")
	expectCode(t, "unlink from another account", a.DeleteUserIdentity(c, "1", id), rec, http.StatusNotFound)
	c, rec = networksContext(http.MethodDelete, "", "UserManager")
	expectCode(t, "unlink", a.DeleteUserIdentity(c, "2", id), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT COUNT(*) FROM auth_user_identities WHERE subject = 'robot'"); got != "0" {
		t.Errorf("robot identity left: %s", got)
	}
	// unlinked, the account takes another one
	c, rec = networksContext(http.MethodPost, `{"subject":"robot2"}`, "UserManager")
	expectCode(t, "replace", a.PostUserIdentities(c, "2"), rec, http.StatusOK)
	if got := queryString(t, pool, "SELECT GROUP_CONCAT(log_action ORDER BY id) FROM log"); got != "users.identity.link,users.identity.unlink,users.identity.link" {
		t.Errorf("logs: %s", got)
	}
}
