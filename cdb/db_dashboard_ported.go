package cdb

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Alerts of the historical collector computed by its feeders and crons, not
// derived from the om3 daemon status.

const (
	DashTypeDuplicateUID        = "duplicate uid"
	DashTypeDuplicateGID        = "duplicate gid"
	DashTypeCompDiffInCluster   = "compliance differences in cluster"
	DashTypeSlowTask            = "slow task"
	compDiffRecentNodesInterval = "INTERVAL 1 DAY"
)

// DashboardUpdateFrozen writes the "node frozen" alert of each frozen node and
// the "service frozen" alert of each frozen instance, and deletes those of the
// nodes and instances thawed or gone. The alerts kept are not rewritten: a run
// with nothing new changes no row.
func (oDb *DB) DashboardUpdateFrozen(ctx context.Context) error {
	var total int64
	count, err := oDb.upsertAlerts(ctx, alertsUpsert{
		source: `SELECT
				"node frozen" AS dash_type,
				n.node_id,
				1 AS dash_severity,
				NOW() AS dash_created,
				NOW() AS dash_updated,
				n.node_env AS dash_env
			FROM nodes n
			WHERE n.node_frozen = 'T'`,
		columns: []string{"dash_type", "node_id", "dash_severity", "dash_created", "dash_updated", "dash_env"},
		update:  []string{"dash_env = s.dash_env"},
	})
	if err != nil {
		return fmt.Errorf("dashboard node frozen: %w", err)
	}
	total += count
	count, err = oDb.execCountContext(ctx, `DELETE d FROM dashboard d
		WHERE d.dash_type = "node frozen" AND NOT EXISTS (
			SELECT 1 FROM nodes n WHERE n.node_id = d.node_id AND n.node_frozen = 'T'
		)`)
	if err != nil {
		return fmt.Errorf("dashboard node frozen: purge: %w", err)
	}
	total += count

	count, err = oDb.upsertAlerts(ctx, alertsUpsert{
		source: `SELECT
				"service frozen" AS dash_type,
				m.svc_id,
				m.node_id,
				1 AS dash_severity,
				NOW() AS dash_created,
				NOW() AS dash_updated,
				IFNULL(s.svc_env, '') AS dash_env
			FROM svcmon m
			JOIN services s ON s.svc_id = m.svc_id
			WHERE m.mon_frozen > 0`,
		columns: []string{"dash_type", "svc_id", "node_id", "dash_severity", "dash_created", "dash_updated", "dash_env"},
		update:  []string{"dash_env = s.dash_env"},
	})
	if err != nil {
		return fmt.Errorf("dashboard service frozen: %w", err)
	}
	total += count
	count, err = oDb.execCountContext(ctx, `DELETE d FROM dashboard d
		WHERE d.dash_type = "service frozen" AND NOT EXISTS (
			SELECT 1 FROM svcmon m
			WHERE m.svc_id = d.svc_id AND m.node_id = d.node_id AND m.mon_frozen > 0
		)`)
	if err != nil {
		return fmt.Errorf("dashboard service frozen: purge: %w", err)
	}
	total += count

	if total > 0 {
		oDb.SetChange("dashboard")
	}
	return nil
}

// DashboardUpdateNodeDuplicateIDs writes a "duplicate uid" alert for each uid
// of the node shared by several user names, or with kind "gid" a "duplicate
// gid" alert for each gid shared by several group names, as of now, the
// instant the node users or groups were written at, and deletes the alerts of
// the node older than now.
func (oDb *DB) DashboardUpdateNodeDuplicateIDs(ctx context.Context, nodeID, kind string, now time.Time) error {
	var dashType, table, idCol, nameCol, fmtS, namesKey string
	switch kind {
	case "uid":
		dashType, table, idCol, nameCol = DashTypeDuplicateUID, "node_users", "user_id", "user_name"
		fmtS, namesKey = "uid %(uid)s is used by users %(usernames)s", "usernames"
	case "gid":
		dashType, table, idCol, nameCol = DashTypeDuplicateGID, "node_groups", "group_id", "group_name"
		fmtS, namesKey = "gid %(gid)s is used by groups %(groupnames)s", "groupnames"
	default:
		return fmt.Errorf("dashboard duplicate ids: unsupported kind %q", kind)
	}
	dict := fmt.Sprintf("JSON_OBJECT('%s', u.id, '%s', u.names)", kind, namesKey)
	source := fmt.Sprintf(`SELECT
			? AS dash_type,
			u.node_id,
			IF(n.node_env = 'PRD', 1, 0) AS dash_severity,
			? AS dash_fmt,
			%[1]s AS dash_dict,
			MD5(%[1]s) AS dash_dict_md5,
			? AS dash_created,
			? AS dash_updated,
			n.node_env AS dash_env,
			CAST(u.id AS CHAR) AS dash_instance
		FROM (
			SELECT node_id, %[2]s AS id, GROUP_CONCAT(%[3]s ORDER BY %[3]s) AS names
			FROM %[4]s
			WHERE node_id = ? AND %[2]s IS NOT NULL
			GROUP BY node_id, %[2]s
			HAVING COUNT(*) > 1
		) u
		JOIN nodes n ON n.node_id = u.node_id`, dict, idCol, nameCol, table)
	total, err := oDb.upsertAlerts(ctx, alertsUpsert{
		source:  source,
		args:    []any{dashType, fmtS, now, now, nodeID},
		columns: []string{"dash_type", "node_id", "dash_severity", "dash_fmt", "dash_dict", "dash_dict_md5", "dash_created", "dash_updated", "dash_env", "dash_instance"},
		update: []string{"dash_severity = s.dash_severity", "dash_dict = s.dash_dict",
			"dash_dict_md5 = s.dash_dict_md5", "dash_env = s.dash_env", "dash_updated = s.dash_updated"},
	})
	if err != nil {
		return fmt.Errorf("dashboard %s: %w", dashType, err)
	}
	count, err := oDb.execCountContext(ctx, "DELETE FROM dashboard WHERE node_id = ? AND dash_type = ? AND dash_updated < ?",
		nodeID, dashType, now)
	if err != nil {
		return fmt.Errorf("dashboard %s: purge: %w", dashType, err)
	}
	if total+count > 0 {
		oDb.SetChange("dashboard")
	}
	return nil
}

// DashboardUpdateCompDiff writes, for each service whose nodes do not agree
// on the status of a compliance module, a "compliance differences in
// cluster" alert counting those modules, as update_dash_compdiff_svc() of the
// historical collector: all nodes ok, all nodes in error or not applicable
// on some nodes are no difference. The nodes are those that reported the
// service in the last day. The alerts of the services without difference are
// deleted.
func (oDb *DB) DashboardUpdateCompDiff(ctx context.Context) error {
	// One instant for the alerts written and the purge of the others.
	now, err := oDb.databaseNow(ctx)
	if err != nil {
		return err
	}
	rows, err := oDb.DB.QueryContext(ctx, `
		SELECT d.svc_id, d.n, IFNULL(s.svc_env, ''),
			GROUP_CONCAT(DISTINCT nd.nodename ORDER BY nd.nodename SEPARATOR ',')
		FROM (
			SELECT t.svc_id, COUNT(*) AS n
			FROM (
				SELECT m.svc_id, cs.run_module,
					COUNT(DISTINCT cs.run_status) AS nstatus,
					MAX(cs.run_status = 2) AS has_na
				FROM svcmon m
				JOIN comp_status cs ON cs.node_id = m.node_id AND IFNULL(cs.svc_id, '') = ''
				LEFT JOIN nodes mn ON mn.node_id = m.node_id
				WHERE `+lastSeen("m.mon_updated", "mn.last_comm")+` > DATE_SUB(NOW(), `+compDiffRecentNodesInterval+`)
				GROUP BY m.svc_id, cs.run_module
				HAVING nstatus > 2 OR (nstatus = 2 AND has_na = 0)
			) t
			GROUP BY t.svc_id
		) d
		JOIN svcmon m ON m.svc_id = d.svc_id
		JOIN nodes nd ON nd.node_id = m.node_id AND `+lastSeen("m.mon_updated", "nd.last_comm")+` > DATE_SUB(NOW(), `+compDiffRecentNodesInterval+`)
		LEFT JOIN services s ON s.svc_id = d.svc_id
		GROUP BY d.svc_id, d.n, s.svc_env`)
	if err != nil {
		return fmt.Errorf("dashboard compliance differences: %w", err)
	}
	var alerts [][]any
	for rows.Next() {
		var (
			svcID, env, nodes string
			n                 int64
		)
		if err := rows.Scan(&svcID, &n, &env, &nodes); err != nil {
			_ = rows.Close()
			return fmt.Errorf("dashboard compliance differences: scan: %w", err)
		}
		sev := 0
		if env == "PRD" {
			sev = 1
		}
		dict, err := json.Marshal(map[string]any{"n": n, "nodes": truncatedNodeList(strings.Split(nodes, ","), 50)})
		if err != nil {
			_ = rows.Close()
			return err
		}
		alerts = append(alerts, []any{DashTypeCompDiffInCluster, svcID, sev,
			"%(n)s compliance differences in cluster %(nodes)s", string(dict),
			fmt.Sprintf("%x", md5.Sum(dict)), now, now, env})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dashboard compliance differences: %w", err)
	}

	var total int64
	columns := []string{"dash_type", "svc_id", "dash_severity", "dash_fmt", "dash_dict", "dash_dict_md5", "dash_created", "dash_updated", "dash_env"}
	for start := 0; start < len(alerts); start += 500 {
		end := min(start+500, len(alerts))
		source, args := givenRows(columns, alerts[start:end])
		count, err := oDb.upsertAlerts(ctx, alertsUpsert{
			source:  source,
			args:    args,
			columns: columns,
			update: []string{"dash_severity = s.dash_severity", "dash_dict = s.dash_dict",
				"dash_dict_md5 = s.dash_dict_md5", "dash_env = s.dash_env", "dash_updated = s.dash_updated"},
		})
		if err != nil {
			return fmt.Errorf("dashboard compliance differences: %w", err)
		}
		total += count
	}
	count, err := oDb.execCountContext(ctx, "DELETE FROM dashboard WHERE dash_type = ? AND (dash_updated < ? OR dash_updated IS NULL)",
		DashTypeCompDiffInCluster, now)
	if err != nil {
		return fmt.Errorf("dashboard compliance differences: purge: %w", err)
	}
	if total+count > 0 {
		oDb.SetChange("dashboard")
	}
	return nil
}

// DashboardUpdateSlowTask writes the "slow task" alert when n feeds have waited
// for a worker for more than 5 minutes, as the task_feed_monitor() of the
// historical collector for its feed tasks, and deletes it when none has.
func (oDb *DB) DashboardUpdateSlowTask(ctx context.Context, n int) error {
	var (
		count int64
		err   error
	)
	if n == 0 {
		count, err = oDb.execCountContext(ctx, "DELETE FROM dashboard WHERE dash_type = ?", DashTypeSlowTask)
	} else {
		count, err = oDb.upsertAlerts(ctx, alertsUpsert{
			source: `SELECT
				? AS dash_type,
				3 AS dash_severity,
				"%(n)s feeds waiting for more than 5 minutes" AS dash_fmt,
				JSON_OBJECT('n', ?) AS dash_dict,
				NOW() AS dash_created,
				NOW() AS dash_updated,
				"PRD" AS dash_env`,
			args:    []any{DashTypeSlowTask, fmt.Sprint(n)},
			columns: []string{"dash_type", "dash_severity", "dash_fmt", "dash_dict", "dash_created", "dash_updated", "dash_env"},
			update:  []string{"dash_dict = s.dash_dict", "dash_updated = s.dash_updated"},
		})
	}
	if err != nil {
		return fmt.Errorf("dashboard slow task: %w", err)
	}
	if count > 0 {
		oDb.SetChange("dashboard")
	}
	return nil
}

// truncatedNodeList joins the nodes with commas, dropping the last ones while
// the text is longer than limit, their count given as ", ... (+n)".
func truncatedNodeList(nodes []string, limit int) string {
	s := strings.Join(nodes, ",")
	for skip := 1; len(s) >= limit && len(nodes) > 1; skip++ {
		nodes = nodes[:len(nodes)-1]
		s = strings.Join(nodes, ",") + fmt.Sprintf(", ... (+%d)", skip)
	}
	return s
}
