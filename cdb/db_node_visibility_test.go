package cdb

import (
	"context"
	"testing"
)

// TestNodeSubListsFollowTheApp checks the checks, compliance runs and alerts
// of a node follow its app, as the nodes list, not its team_responsible: a
// node registered anonymously, of team Everybody, is not shown to every user.
func TestNodeSubListsFollowTheApp(t *testing.T) {
	db := testMariaDB(t,
		"CREATE TABLE nodes (node_id char(36), nodename varchar(64), app varchar(64), team_responsible varchar(64))",
		"CREATE TABLE services (svc_id char(36), svcname varchar(64), svc_app varchar(64))",
		"CREATE TABLE apps (id int, app varchar(64))",
		"CREATE TABLE apps_responsibles (app_id int, group_id int)",
		"CREATE TABLE auth_group (id int, role varchar(64))",
		"CREATE TABLE checks_live (id int, node_id char(36), svc_id char(36), chk_type varchar(32), chk_instance varchar(64))",
		"CREATE TABLE dashboard (id int, node_id char(36), svc_id char(36))",
		"INSERT INTO apps VALUES (1, 'A')",
		"INSERT INTO apps_responsibles VALUES (1, 10)",
		"INSERT INTO auth_group VALUES (10, 'teamA'), (20, 'teamB')",
		"INSERT INTO nodes VALUES ('n1', 'node1', 'A', 'Everybody')",
		"INSERT INTO checks_live VALUES (1, 'n1', '', 'fs_u', '/')",
		"INSERT INTO dashboard VALUES (1, 'n1', '')",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	for _, tc := range []struct {
		groups []string
		want   int
	}{{[]string{"teamA"}, 1}, {[]string{"teamB"}, 0}, {nil, 0}} {
		checks, err := odb.GetNodeChecks(ctx, "n1", ListParams{Groups: tc.groups, SelectExprs: []string{"checks_live.id"}, Props: []string{"id"}})
		if err != nil {
			t.Fatal(err)
		}
		alerts, err := odb.GetNodeAlerts(ctx, "n1", ListParams{Groups: tc.groups, SelectExprs: []string{"dashboard.id"}, Props: []string{"id"}})
		if err != nil {
			t.Fatal(err)
		}
		ids, err := odb.PublishedNodeIDsForGroups(ctx, tc.groups)
		if err != nil {
			t.Fatal(err)
		}
		if len(checks) != tc.want || len(alerts) != tc.want || len(ids) != tc.want {
			t.Errorf("groups %v: %d checks, %d alerts, %d nodes, want %d", tc.groups, len(checks), len(alerts), len(ids), tc.want)
		}
	}
	if _, args, err := buildCompStatusQuery([]string{"teamB"}, false, []string{"comp_status.id"}); err != nil || len(args) != 1 {
		t.Errorf("compliance runs: %v, %v", args, err)
	}
}
