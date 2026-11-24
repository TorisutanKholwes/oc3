package serverhandlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/util/echolog"
	"github.com/opensvc/oc3/util/logkey"
)

// PostAgentWake handles POST /agent/wake: a node asks to wake a powered off
// virtual machine node of its own cluster. The collector finds the container
// resource whose virtual machine has the machine uuid the node reported, on
// a hypervisor reporting to this collector, and queues its start there.
//
// The caller is a node, authenticated as such: it can only name a node of its
// own cluster, and only the start of the one container running that node is
// queued, never another action. A start already queued and not done yet is
// returned rather than queued twice, as every relay of the cluster may ask.
func (a *Api) PostAgentWake(c echo.Context, params server.PostAgentWakeParams) error {
	log := echolog.GetLogHandler(c, "PostAgentWake")
	ctx := c.Request().Context()

	if !IsAuthByNode(c) {
		return JSONProblem(c, http.StatusForbidden, "node authentication required")
	}
	if params.Nodename == "" {
		return JSONProblem(c, http.StatusBadRequest, "nodename is required")
	}
	callerID, _ := c.Get(XNodeID).(string)
	if callerID == "" {
		return JSONProblem(c, http.StatusForbidden, "node authentication required")
	}
	caller, err := a.ODB.NodeByNodeID(ctx, callerID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read the calling node", err))
	}
	if caller == nil || caller.ClusterID == "" {
		return JSONProblemf(c, http.StatusForbidden, "the calling node has no cluster")
	}

	// A node of another cluster is answered as one that does not exist: the
	// caller learns nothing of the nodes it can not wake.
	targetID, err := a.ODB.NodeIDByNodenameAndCluster(ctx, params.Nodename, caller.ClusterID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read the node to wake", err))
	}
	if targetID == "" {
		return JSONProblemf(c, http.StatusNotFound, "no node %s in the cluster of %s", params.Nodename, caller.Nodename)
	}

	machineUUID, err := a.ODB.NodeMachineUUID(ctx, targetID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read the machine uuid", err))
	}
	if machineUUID == "" {
		return JSONProblemf(c, http.StatusConflict, "node %s reported no machine uuid: run om node push asset on it while it is up", params.Nodename)
	}

	containers, err := a.ODB.ContainersByMachineUUID(ctx, machineUUID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read the resource info", err))
	}
	container, err := pickWakeContainer(containers, targetID, params.Nodename, machineUUID)
	if err != nil {
		return actionProblem(c, err)
	}

	hv, err := a.ODB.NodeActionTargetByID(ctx, container.NodeID)
	if err != nil {
		log.Error("cannot read the hypervisor node", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the hypervisor node")
	}
	if hv == nil {
		return JSONProblemf(c, http.StatusNotFound, "the hypervisor node of %s is unknown", params.Nodename)
	}
	svc, err := a.ODB.ServiceBySvcIDOrName(ctx, container.SvcID, nil, true)
	if err != nil {
		log.Error("cannot read the hypervisor service", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the hypervisor service")
	}
	if svc == nil {
		return JSONProblemf(c, http.StatusNotFound, "the service holding the container of %s is unknown", params.Nodename)
	}
	agentVersion, err := a.ODB.NodeAgentVersion(ctx, hv.NodeID)
	if err != nil {
		log.Error("cannot read the agent version", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the hypervisor node")
	}

	act := actionActor{email: "node " + caller.Nodename}

	// The command the start would queue, every check of the queueing passed,
	// to find one queued before.
	dry := act
	dry.dryRun = true
	planned, err := a.enqueueServiceCommand(dry, log, ctx, svc, hv, agentVersion, "start", container.RID, true)
	if err != nil {
		return actionProblem(c, err)
	}
	info := server.WakeAgentInfo{
		Nodename:   params.Nodename,
		Hypervisor: hv.Nodename,
		Path:       svc.Svcname,
		Rid:        container.RID,
	}
	pendingID, err := a.ODB.PendingServiceActionID(ctx, hv.NodeID, svc.SvcID, planned.Command)
	if err != nil {
		log.Error("cannot read the action queue", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the action queue")
	}
	if pendingID > 0 {
		info.ActionId = pendingID
		return c.JSON(http.StatusOK, info)
	}

	queued, err := a.enqueueServiceCommand(act, log, ctx, svc, hv, agentVersion, "start", container.RID, true)
	if err != nil {
		return actionProblem(c, err)
	}
	log.Info("wake queued", "nodename", params.Nodename, "hypervisor", hv.Nodename, "path", svc.Svcname, "rid", container.RID, "action_id", queued.ID)
	info.ActionId = queued.ID
	info.Queued = true
	return c.JSON(http.StatusOK, info)
}

// pickWakeContainer returns the one container running the node: none is a
// 404, several a 409 naming them, as starting one of them at random could
// start the wrong virtual machine. A row of the node itself is not one: a node
// does not run in its own container.
func pickWakeContainer(containers []cdb.WakeContainer, targetID, nodename, machineUUID string) (cdb.WakeContainer, error) {
	var l []cdb.WakeContainer
	for _, w := range containers {
		if w.NodeID == targetID || w.RID == "" {
			continue
		}
		l = append(l, w)
	}
	switch len(l) {
	case 0:
		return cdb.WakeContainer{}, refuseAction(http.StatusNotFound,
			"no container reports the machine uuid %s of node %s: its hypervisor must run opensvc and report to this collector", machineUUID, nodename)
	case 1:
		return l[0], nil
	default:
		names := make([]string, len(l))
		for i, w := range l {
			names[i] = fmt.Sprintf("%s:%s@%s", w.SvcID, w.RID, w.NodeID)
		}
		return cdb.WakeContainer{}, refuseAction(http.StatusConflict,
			"%d containers report the machine uuid %s of node %s: %s", len(l), machineUUID, nodename, strings.Join(names, ", "))
	}
}
