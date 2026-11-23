package cdb

import (
	"context"
	"slices"
	"testing"
	"time"
)

const pushSSH = "ssh -o StrictHostKeyChecking=no -o CheckHostIP=no -o ForwardX11=no -o ConnectTimeout=5 -o PasswordAuthentication=no opensvc@n1 -- sudo nodemgr "

// The power action of a command is read from the forms the queueing writes, a
// pull node reading the bare action, a push node an ssh invocation.
func TestPowerCommand(t *testing.T) {
	for command, want := range map[string]string{
		"reboot":                    "reboot",
		"shutdown":                  "shutdown",
		pushSSH + "reboot":          "reboot",
		pushSSH + "shutdown":        "shutdown",
		"schedule_reboot":           "",
		"unschedule_reboot":         "",
		pushSSH + "schedule_reboot": "",
		"freeze --local":            "",
		"svc -s reboot stop":        "",
		"":                          "",
	} {
		if got := PowerCommand(command); got != want {
			t.Errorf("%q: got %q, want %q", command, got, want)
		}
	}
}

var powerActionTestTables = []string{
	"CREATE TABLE action_queue (id int AUTO_INCREMENT PRIMARY KEY, status varchar(1) DEFAULT 'W', command text NOT NULL," +
		" date_queued timestamp NOT NULL DEFAULT current_timestamp(), date_dequeued timestamp NOT NULL DEFAULT '0000-00-00 00:00:00'," +
		" ret int DEFAULT NULL, stdout text DEFAULT NULL, stderr text DEFAULT NULL, action_type varchar(8) DEFAULT NULL," +
		" node_id char(36) CHARACTER SET ascii DEFAULT '', svc_id char(36) CHARACTER SET ascii DEFAULT '')",
	"CREATE TABLE nodes (node_id char(36) CHARACTER SET ascii PRIMARY KEY, nodename varchar(256), last_comm datetime(3))",
	"CREATE TABLE hbmon (id bigint AUTO_INCREMENT PRIMARY KEY, node_id char(36) CHARACTER SET ascii DEFAULT ''," +
		" peer_node_id char(36) CHARACTER SET ascii DEFAULT '', name varchar(64) DEFAULT '', beating tinyint(1) DEFAULT 0)",
}

func powerActionIDs(l []PowerAction) []int {
	ids := make([]int, 0, len(l))
	for _, a := range l {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	return ids
}

// The open power actions are the reboots and shutdowns a node took, and
// closing one leaves an action whose result the agent posted as it is.
func TestActionQOpenPowerActions(t *testing.T) {
	db := testMariaDB(t, powerActionTestTables...)
	testExec(t, db,
		"INSERT INTO nodes VALUES ('n1', 'node1', NOW()), ('n2', 'node2', NOW())",
		"INSERT INTO action_queue (id, status, command, node_id, date_dequeued) VALUES"+
			" (1, 'R', 'reboot', 'n1', NOW()),"+
			" (2, 'S', '"+pushSSH+"shutdown', 'n1', NOW()),"+
			" (3, 'W', 'reboot', 'n1', 0),"+
			" (4, 'T', 'reboot', 'n1', NOW()),"+
			" (5, 'R', 'schedule_reboot', 'n1', NOW()),"+
			" (6, 'R', 'reboot', 'n2', NOW())",
	)
	odb := testDashboardDB(db)
	ctx := context.Background()
	l, err := odb.ActionQOpenPowerActions(ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if got := powerActionIDs(l); !slices.Equal(got, []int{1, 2}) {
		t.Fatalf("got %v, want [1 2]", got)
	}
	for _, a := range l {
		if a.Nodename != "node1" || (a.ID == 1 && a.Action != "reboot") || (a.ID == 2 && a.Action != "shutdown") {
			t.Errorf("unexpected %+v", a)
		}
	}

	if closed, err := odb.ActionQClosePowerAction(ctx, 1, "node node1 booted"); err != nil || !closed {
		t.Fatalf("close 1: %v %v", closed, err)
	}
	if closed, err := odb.ActionQClosePowerAction(ctx, 4, "node node1 booted"); err != nil || closed {
		t.Fatalf("close 4, done by the agent: %v %v", closed, err)
	}
	var (
		status string
		ret    int
		stdout string
	)
	if err := db.QueryRow("SELECT status, ret, stdout FROM action_queue WHERE id = 1").Scan(&status, &ret, &stdout); err != nil {
		t.Fatal(err)
	}
	if status != "T" || ret != 0 || stdout != "node node1 booted" {
		t.Errorf("action 1: %s %d %q", status, ret, stdout)
	}
}

// A shutdown is closed once its node is silent past the grace: no
// communication when no peer reports it, no peer seeing it beating otherwise.
func TestActionQShutdownsOfSilentNodes(t *testing.T) {
	db := testMariaDB(t, powerActionTestTables...)
	old := "DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
	testExec(t, db,
		"INSERT INTO nodes VALUES"+
			" ('lone-silent', 'a', "+old+"), ('lone-alive', 'b', NOW()),"+
			" ('peer-silent', 'c', NOW()), ('peer-beating', 'd', NOW()), ('recent', 'e', "+old+")",
		"INSERT INTO hbmon (node_id, peer_node_id, name, beating) VALUES"+
			" ('x', 'peer-silent', '1', 2), ('y', 'peer-silent', '1', 2),"+
			" ('x', 'peer-beating', '1', 2), ('y', 'peer-beating', '1', 1)",
		"INSERT INTO action_queue (id, status, command, node_id, date_dequeued) VALUES"+
			" (1, 'R', 'shutdown', 'lone-silent', "+old+"),"+
			" (2, 'R', 'shutdown', 'lone-alive', "+old+"),"+
			" (3, 'S', 'shutdown', 'peer-silent', "+old+"),"+
			" (4, 'R', 'shutdown', 'peer-beating', "+old+"),"+
			" (5, 'R', 'shutdown', 'recent', NOW()),"+
			" (6, 'R', 'reboot', 'lone-silent', "+old+")",
	)
	odb := testDashboardDB(db)
	l, err := odb.ActionQShutdownsOfSilentNodes(context.Background(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := powerActionIDs(l); !slices.Equal(got, []int{1, 3}) {
		t.Fatalf("got %v, want [1 3]", got)
	}
}
