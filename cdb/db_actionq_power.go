package cdb

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PowerActions are the node actions taking the node down: the agent running
// one never posts its result, the node going down under it, so the collector
// closes them itself, a reboot when the node is seen booted again, a shutdown
// when the node goes silent.
var PowerActions = []string{"reboot", "shutdown"}

// pushCommandPrefix is the end of the ssh invocation of a push node action, the
// action following it (the serverhandlers nodeActionCommand).
const pushCommandPrefix = " nodemgr "

// PowerAction is an open reboot or shutdown action of the action queue.
type PowerAction struct {
	ID           int
	NodeID       string
	Nodename     string
	Action       string
	DateDequeued time.Time
}

// PowerCommand returns the power action a queued command runs, "reboot" or
// "shutdown", or "" for another command. It reads the forms the queueing writes:
// the bare action read by a pull or feed node, and the ssh invocation ending with
// "nodemgr <action>" of a push node. powerCommandCond is its SQL counterpart.
func PowerCommand(command string) string {
	for _, action := range PowerActions {
		if command == action || strings.HasSuffix(command, pushCommandPrefix+action) {
			return action
		}
	}
	return ""
}

// powerCommandCond is the condition on action_queue.command PowerCommand
// accepts for the actions, and its arguments.
func powerCommandCond(actions ...string) (string, []any) {
	conds := make([]string, 0, 2*len(actions))
	args := make([]any, 0, 2*len(actions))
	for _, action := range actions {
		conds = append(conds, "a.command = ?", "a.command LIKE ?")
		args = append(args, action, "%"+pushCommandPrefix+action)
	}
	return "(" + strings.Join(conds, " OR ") + ")", args
}

// openPowerActionStatuses are the statuses of an action an agent took: sent to
// the node, or acknowledged by it as running.
const openPowerActionStatuses = "a.status IN ('S', 'R')"

// ActionQOpenPowerActions returns the reboot and shutdown actions the nodes
// took and did not post the result of.
func (oDb *DB) ActionQOpenPowerActions(ctx context.Context, nodeIDs ...string) ([]PowerAction, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	cond, args := powerCommandCond(PowerActions...)
	query := "SELECT a.id, a.node_id, COALESCE(n.nodename, ''), a.command, a.date_dequeued" +
		" FROM action_queue a LEFT JOIN nodes n ON n.node_id = a.node_id" +
		" WHERE " + openPowerActionStatuses + " AND " + cond +
		" AND a.node_id IN (?" + strings.Repeat(", ?", len(nodeIDs)-1) + ")"
	for _, nodeID := range nodeIDs {
		args = append(args, nodeID)
	}
	return oDb.queryPowerActions(ctx, "actionQOpenPowerActions", query, args...)
}

// ActionQShutdownsOfSilentNodes returns the shutdown actions sent more than
// grace ago to a node gone silent since:
//   - a node no peer reports, its last communication older than grace: only the
//     node refreshes it when it has no peer, a status refreshing it for every
//     node of the cluster,
//   - a node peers report, none of them seeing it beating.
func (oDb *DB) ActionQShutdownsOfSilentNodes(ctx context.Context, grace time.Duration) ([]PowerAction, error) {
	cond, args := powerCommandCond("shutdown")
	seconds := int64(grace / time.Second)
	query := "SELECT a.id, a.node_id, COALESCE(n.nodename, ''), a.command, a.date_dequeued" +
		" FROM action_queue a JOIN nodes n ON n.node_id = a.node_id" +
		" WHERE " + openPowerActionStatuses + " AND " + cond +
		" AND a.date_dequeued > 0 AND a.date_dequeued < DATE_SUB(NOW(), INTERVAL ? SECOND)" +
		" AND (" +
		"  (NOT EXISTS (SELECT 1 FROM hbmon h WHERE h.peer_node_id = a.node_id)" +
		"   AND (n.last_comm IS NULL OR n.last_comm < DATE_SUB(NOW(), INTERVAL ? SECOND)))" +
		"  OR (EXISTS (SELECT 1 FROM hbmon h WHERE h.peer_node_id = a.node_id)" +
		"   AND NOT EXISTS (SELECT 1 FROM hbmon h WHERE h.peer_node_id = a.node_id AND h.beating = 1))" +
		" )"
	args = append(args, seconds, seconds)
	return oDb.queryPowerActions(ctx, "actionQShutdownsOfSilentNodes", query, args...)
}

func (oDb *DB) queryPowerActions(ctx context.Context, name, query string, args ...any) ([]PowerAction, error) {
	rows, err := oDb.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	var l []PowerAction
	for rows.Next() {
		var (
			a       PowerAction
			command string
		)
		if err := rows.Scan(&a.ID, &a.NodeID, &a.Nodename, &command, &a.DateDequeued); err != nil {
			return nil, fmt.Errorf("%s scan: %w", name, err)
		}
		a.Action = PowerCommand(command)
		l = append(l, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s rows: %w", name, err)
	}
	return l, nil
}

// ActionQClosePowerAction ends a reboot or shutdown action as done, with
// stdout saying how the collector told it. An action whose result the agent
// posted meanwhile is left as it is.
func (oDb *DB) ActionQClosePowerAction(ctx context.Context, id int, stdout string) (bool, error) {
	const query = "UPDATE action_queue SET status = 'T', ret = 0, stdout = ?, stderr = '', date_dequeued = NOW()" +
		" WHERE id = ? AND status IN ('S', 'R')"
	n, err := oDb.ExecContextAndCountRowsAffected(ctx, query, stdout, id)
	if err != nil {
		return false, fmt.Errorf("actionQClosePowerAction %d: %w", id, err)
	}
	if n > 0 {
		oDb.SetChange("action_queue")
	}
	return n > 0, nil
}
