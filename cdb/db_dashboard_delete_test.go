package cdb

import (
	"context"
	"slices"
	"testing"
)

func TestDashboardObjectWithTypeDelete(t *testing.T) {
	db := testMariaDB(t, dashboardTestTables...)
	testExec(t, db,
		"INSERT INTO dashboard (dash_type, svc_id, node_id, dash_severity, dash_instance) VALUES"+
			" ('service unavailable', 's1', '', 1, ''), ('service placement', 's1', '', 1, ''),"+
			" ('service unavailable', 's2', '', 1, ''), ('service placement', 's2', '', 1, ''),"+
			" ('service unavailable', 's3', '', 1, '')",
	)
	odb := testDashboardDB(db)
	err := odb.DashboardObjectWithTypeDelete(context.Background(),
		&DashboardObjectType{ObjectID: "s1", DashType: "service unavailable"},
		&DashboardObjectType{ObjectID: "s2", DashType: "service placement"},
		&DashboardObjectType{ObjectID: "s1", DashType: "service unavailable"},
		&DashboardObjectType{ObjectID: "s9", DashType: "service unavailable"},
	)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, a := range testAlerts(t, db) {
		left = append(left, a.SvcID+" "+a.Type)
	}
	want := []string{"s1 service placement", "s2 service unavailable", "s3 service unavailable"}
	if !slices.Equal(left, want) {
		t.Errorf("left %v, want %v", left, want)
	}
	if err := odb.DashboardObjectWithTypeDelete(context.Background()); err != nil {
		t.Errorf("empty list: %v", err)
	}
}
