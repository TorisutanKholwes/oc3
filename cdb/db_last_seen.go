package cdb

import "fmt"

// The ping of an om3 daemon (feed daemon ping) only refreshes nodes.last_comm of
// the nodes of its cluster. It used to also rewrite every svcmon, svcmon_log_last,
// resmon and resmon_log_last row of those nodes, about a quarter of the database
// time of the agent-sim 1000 nodes run, and more as the resources grow.
//
// The time an instance, a resource or their current status log was last
// confirmed is so the latest of its own column, written by the daemon status
// feed, and of the last_comm of its node, written by the daemon status and ping
// feeds: lastSeen.

// lastSeen returns the SQL expression of the latest of the col and lastComm
// datetimes, either of them NULL. It is cast to the precision of col, the
// second, last_comm being to the millisecond.
func lastSeen(col, lastComm string) string {
	return fmt.Sprintf("CAST(COALESCE(GREATEST(%[1]s, %[2]s), %[1]s, %[2]s) AS DATETIME)", col, lastComm)
}

// lastCommOf returns the SQL expression of the last_comm of the node of the
// rows of table, for the queries not joining nodes.
func lastCommOf(table string) string {
	return "(SELECT `nodes`.`last_comm` FROM `nodes` WHERE `nodes`.`node_id` = " + table + ".`node_id`)"
}

// SvcmonUpdatedSQL returns the SQL expression of the time the instance of the
// svcmon row named table was last confirmed.
func SvcmonUpdatedSQL(table string) string {
	return lastSeen(table+".`mon_updated`", lastCommOf(table))
}

// ResmonUpdatedSQL returns the SQL expression of the time the resource of the
// resmon row named table was last confirmed.
func ResmonUpdatedSQL(table string) string {
	return lastSeen(table+".`updated`", lastCommOf(table))
}
