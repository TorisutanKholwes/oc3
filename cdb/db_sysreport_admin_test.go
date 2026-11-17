package cdb

import (
	"context"
	"testing"
)

// TestSysrepAllowAdmin checks, on a MariaDB, that an authorization reads the
// names of its group and filterset, empty once they are gone, and that the
// duplicates are found on the exact pattern, case included.
func TestSysrepAllowAdmin(t *testing.T) {
	pool := testMariaDB(t,
		"CREATE TABLE auth_group (id INT AUTO_INCREMENT PRIMARY KEY, role VARCHAR(255) NOT NULL, privilege CHAR(1) DEFAULT 'F')",
		"CREATE TABLE gen_filtersets (id INT AUTO_INCREMENT PRIMARY KEY, fset_name VARCHAR(30) NOT NULL)",
		"CREATE TABLE sysrep_secure (id INT(11) NOT NULL AUTO_INCREMENT, pattern TEXT NOT NULL, PRIMARY KEY (id))",
		"CREATE TABLE sysrep_allow (id INT(11) NOT NULL AUTO_INCREMENT, pattern TEXT NOT NULL, fset_id INT(11) NOT NULL, group_id INT(11) NOT NULL, PRIMARY KEY (id))",
		"INSERT INTO auth_group (id, role) VALUES (2, 'Ops')",
		"INSERT INTO gen_filtersets (id, fset_name) VALUES (10, 'linux')",
	)
	ctx := context.Background()
	oDb := New(pool)
	oDb.Metrics = testMetrics()
	oDb.CreateSession(nil)

	id, err := oDb.InsertSysrepAllow(ctx, 2, 10, "/etc/.*")
	if err != nil {
		t.Fatal(err)
	}
	row, err := oDb.SysrepAllowByID(ctx, id)
	if err != nil || row == nil || row.GroupName != "Ops" || row.FsetName != "linux" || row.Pattern != "/etc/.*" {
		t.Fatalf("read %+v, %v", row, err)
	}
	if other, dup, err := oDb.SysrepAllowID(ctx, 2, 10, "/etc/.*"); err != nil || !dup || other != id {
		t.Errorf("duplicate %d %v %v", other, dup, err)
	}
	if _, dup, err := oDb.SysrepAllowID(ctx, 2, 10, "/ETC/.*"); err != nil || dup {
		t.Errorf("a pattern differing by case is a duplicate: %v %v", dup, err)
	}
	for _, s := range []string{"DELETE FROM auth_group", "DELETE FROM gen_filtersets"} {
		if _, err := pool.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	row, err = oDb.SysrepAllowByID(ctx, id)
	if err != nil || row == nil || row.GroupName != "" || row.FsetName != "" || row.GroupID != 2 || row.FsetID != 10 {
		t.Errorf("read without group and filterset %+v, %v", row, err)
	}
	if err := oDb.DeleteSysrepAllow(ctx, id); err != nil {
		t.Fatal(err)
	}
	if row, err := oDb.SysrepAllowByID(ctx, id); err != nil || row != nil {
		t.Errorf("read after delete %+v, %v", row, err)
	}

	pid, err := oDb.InsertSysrepSecurePattern(ctx, ".*/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if other, dup, err := oDb.SysrepSecurePatternID(ctx, ".*/etc/shadow"); err != nil || !dup || other != pid {
		t.Errorf("duplicate pattern %d %v %v", other, dup, err)
	}
	if p, found, err := oDb.SysrepSecurePatternByID(ctx, pid); err != nil || !found || p != ".*/etc/shadow" {
		t.Errorf("read pattern %q %v %v", p, found, err)
	}
}
