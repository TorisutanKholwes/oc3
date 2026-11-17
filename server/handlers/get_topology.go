package serverhandlers

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/util/echolog"
)

func splitList(s *string) []string {
	if s == nil {
		return nil
	}
	var l []string
	for _, v := range strings.Split(*s, ",") {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(l, v) {
			l = append(l, v)
		}
	}
	return l
}

// GetTopology handles GET /topology, as the historical collector's
// json_topo_data.
func (a *Api) GetTopology(c echo.Context, params server.GetTopologyParams) error {
	log := echolog.GetLogHandler(c, "GetTopology")
	ctx := c.Request().Context()

	layers := splitList(&params.Display)
	if len(layers) == 0 {
		return JSONProblemf(c, http.StatusBadRequest, "display must name at least one layer")
	}
	known := cdb.TopologyLayers()
	for _, l := range layers {
		if !slices.Contains(known, l) {
			return JSONProblemf(c, http.StatusBadRequest, "unknown layer %q, expected one of %s", l, strings.Join(known, ", "))
		}
	}
	r := cdb.TopologyRequest{
		NodeIDs:   splitList(params.NodeIds),
		SvcIDs:    splitList(params.SvcIds),
		Layers:    layers,
		Groups:    UserGroupsFromContext(c),
		IsManager: IsManager(c),
	}
	for _, s := range splitList(params.AppIds) {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return JSONProblemf(c, http.StatusBadRequest, "app_ids must be integers, got %q", s)
		}
		r.AppIDs = append(r.AppIDs, id)
	}
	if n := len(r.NodeIDs) + len(r.SvcIDs) + len(r.AppIDs); n > cdb.MaxTopologyObjects {
		return JSONProblemf(c, http.StatusBadRequest, "%d objects to start from, more than %d", n, cdb.MaxTopologyObjects)
	}
	log.Info("called", "nodes", len(r.NodeIDs), "services", len(r.SvcIDs), "apps", len(r.AppIDs), "display", layers)

	t, err := a.ODB.GetTopology(ctx, r)
	if errors.Is(err, cdb.ErrTopologyTooLarge) {
		return JSONProblemf(c, http.StatusBadRequest, "more than %d nodes and services to draw: narrow the selection", cdb.MaxTopologyObjects)
	}
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot build the topology", err))
	}
	return c.JSON(http.StatusOK, t)
}
