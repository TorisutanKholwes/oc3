package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

var TaskRefreshBActionErrors = Task{
	name:    "refresh_b_action_errors",
	period:  24 * time.Hour,
	fn:      taskRefreshBActionErrorsRun,
	timeout: time.Minute,
}

func taskRefreshBActionErrorsRun(ctx context.Context, task *Task) error {
	odb, err := task.DBX(ctx)
	if err != nil {
		return err
	}
	defer odb.Rollback()

	if err := odb.BActionErrorsRefresh(ctx); err != nil {
		return err
	}

	return odb.Commit()
}

// TaskCloseShutdownActions closes the shutdown actions of the nodes gone
// silent since: the agent running one never posts its result, the node
// going down under it, and a node shut down does not come back to say it.
// A node seen booted again closes its shutdown as its reboot, in the daemon
// status feed.
var TaskCloseShutdownActions = Task{
	name:    "close_shutdown",
	period:  time.Minute,
	fn:      taskCloseShutdownActionsRun,
	timeout: time.Minute,
}

func taskCloseShutdownActionsRun(ctx context.Context, task *Task) error {
	grace, err := maxAge("close_shutdown")
	if err != nil {
		return err
	}
	odb, err := task.DBX(ctx)
	if err != nil {
		return err
	}
	defer odb.Rollback()

	actions, err := odb.ActionQShutdownsOfSilentNodes(ctx, grace)
	if err != nil {
		return err
	}
	for _, a := range actions {
		stdout := fmt.Sprintf("node %s silent since the shutdown", a.Nodename)
		closed, err := odb.ActionQClosePowerAction(ctx, a.ID, stdout)
		if err != nil {
			return err
		}
		if closed {
			slog.Info(fmt.Sprintf("close_shutdown: shutdown action %d of node %s closed: %s", a.ID, a.Nodename, stdout))
		}
	}

	return odb.Commit()
}
