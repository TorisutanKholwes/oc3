package serverhandlers

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/labstack/echo/v4"
)

// provisioningRightsStore is the database access of the provisioning rights.
type provisioningRightsStore interface {
	AppsForGroups(ctx context.Context, groups []string) ([]string, error)
	ClusterNodeApps(ctx context.Context, clusterID string) ([]string, error)
}

// requireProvisioningApps checks the user, NodeManager, may provision the
// cluster clusterID with nodes of the apps: responsible for the apps, and
// for every node the collector has in the cluster, whose members enroll the
// nodes bootstrapped into it. A Manager is responsible for all. clusterID
// empty checks the apps only, an empty app is ignored.
func requireProvisioningApps(c echo.Context, ctx context.Context, log *slog.Logger, store provisioningRightsStore, clusterID string, apps ...string) error {
	if err := requireProvisioning(c); err != nil {
		return err
	}
	if IsManager(c) {
		return nil
	}
	responsible, err := store.AppsForGroups(ctx, UserGroupsFromContext(c))
	if err != nil {
		log.Error("cannot list the apps of the user", "error", err)
		return denyRequest(c, http.StatusInternalServerError, "cannot check the responsibility")
	}
	isResponsible := func(app string) bool {
		return slices.ContainsFunc(responsible, func(s string) bool { return strings.EqualFold(s, app) })
	}
	for _, app := range apps {
		if app != "" && !isResponsible(app) {
			return denyRequest(c, http.StatusForbidden, "you are not responsible for the app %s", app)
		}
	}
	if clusterID == "" {
		return nil
	}
	nodeApps, err := store.ClusterNodeApps(ctx, clusterID)
	if err != nil {
		log.Error("cannot list the apps of the cluster nodes", "error", err)
		return denyRequest(c, http.StatusInternalServerError, "cannot check the responsibility")
	}
	for _, app := range nodeApps {
		if !isResponsible(app) {
			return denyRequest(c, http.StatusForbidden, "you are not responsible for every node of the cluster %s", clusterID)
		}
	}
	return nil
}
