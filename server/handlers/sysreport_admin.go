package serverhandlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/util/echolog"
	"github.com/opensvc/oc3/util/logkey"
)

// sysrepPatternMaxLen is the size of the text column holding the patterns.
const sysrepPatternMaxLen = 65535

// requireUserAuth refuses the requests not made by a user: the sysreport access
// rules say which files are sensitive and who can read them, nothing a node
// needs to know.
func requireUserAuth(c echo.Context) error {
	if !IsAuthByUser(c) {
		return denyRequest(c, http.StatusUnauthorized, "user authentication required")
	}
	return nil
}

// checkSysrepPattern validates a secure pattern or the pattern of an
// authorization: a regular expression compiled as the sysreport access checks
// compile it, anchored at the start of the path. The error is meant for the
// client.
func checkSysrepPattern(pattern *string) (string, error) {
	if pattern == nil || strings.TrimSpace(*pattern) == "" {
		return "", errors.New("pattern is mandatory")
	}
	if len(*pattern) > sysrepPatternMaxLen {
		return "", fmt.Errorf("pattern is longer than %d bytes", sysrepPatternMaxLen)
	}
	if _, err := anchored(*pattern); err != nil {
		return "", fmt.Errorf("invalid regular expression: %s", err)
	}
	return *pattern, nil
}

// logSysrep writes an audit entry of a sysreport access rule change. A failure
// is logged and does not fail the change.
func (a *Api) logSysrep(ctx context.Context, c echo.Context, log *slog.Logger, action, format string, dict map[string]any) {
	user, _ := c.Get(XUserEmail).(string)
	if err := a.ODB.Log(ctx, cdb.LogEntry{
		Action: action,
		User:   user,
		Fmt:    format,
		Dict:   dict,
		Level:  "info",
	}); err != nil {
		log.Error("cannot write audit log", logkey.Error, err)
	}
	if err := a.ODB.Session.NotifyChanges(ctx); err != nil {
		log.Error("cannot notify changes", logkey.Error, err)
	}
}

// GetSysreportSecurePatterns handles GET /sysreport/secure_patterns.
func (a *Api) GetSysreportSecurePatterns(c echo.Context, params server.GetSysreportSecurePatternsParams) error {
	if err := requireUserAuth(c); err != nil {
		return err
	}
	return a.handleList(c, "GetSysreportSecurePatterns", "sysrep_secure", listEndpointParams{
		props: params.Props, limit: params.Limit, offset: params.Offset,
		meta: params.Meta, stats: params.Stats, orderby: params.Orderby, groupby: params.Groupby,
		filter: params.Filter,
	}, func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
		return a.ODB.GetSysrepSecurePatterns(ctx, p)
	})
}

// GetSysreportSecurePattern handles GET /sysreport/secure_patterns/{id}.
func (a *Api) GetSysreportSecurePattern(c echo.Context, id int, params server.GetSysreportSecurePatternParams) error {
	if err := requireUserAuth(c); err != nil {
		return err
	}
	return a.getSysreportSecurePattern(c, "GetSysreportSecurePattern", int64(id), params.Props)
}

func (a *Api) getSysreportSecurePattern(c echo.Context, name string, id int64, props *server.InQueryProps) error {
	return a.handleItem(c, name, "sysrep_secure", "id", strconv.FormatInt(id, 10), listEndpointParams{props: props},
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetSysrepSecurePattern(ctx, id, p)
		})
}

// PostSysreportSecurePatterns handles POST /sysreport/secure_patterns.
func (a *Api) PostSysreportSecurePatterns(c echo.Context) error {
	log := echolog.GetLogHandler(c, "PostSysreportSecurePatterns")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()
	if err := requireManager(c); err != nil {
		return err
	}
	var body server.PostSysreportSecurePatternsJSONRequestBody
	if err := c.Bind(&body); err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	pattern, err := checkSysrepPattern(&body.Pattern)
	if err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	if other, dup, err := a.ODB.SysrepSecurePatternID(ctx, pattern); err != nil {
		log.Error("cannot check duplicates", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot check duplicates")
	} else if dup {
		return JSONProblemf(c, http.StatusConflict, "secure pattern already exists: %d", other)
	}
	id, err := a.ODB.InsertSysrepSecurePattern(ctx, pattern)
	if err != nil {
		log.Error("cannot create the secure pattern", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot create the secure pattern")
	}
	a.logSysrep(ctx, c, log, "sysreport.secure_pattern.create",
		"pattern %(s)s created.", map[string]any{"s": pattern})
	return a.getSysreportSecurePattern(c, "PostSysreportSecurePatterns", id, nil)
}

// DeleteSysreportSecurePattern handles DELETE /sysreport/secure_patterns/{id}.
func (a *Api) DeleteSysreportSecurePattern(c echo.Context, id int) error {
	log := echolog.GetLogHandler(c, "DeleteSysreportSecurePattern")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()
	if err := requireManager(c); err != nil {
		return err
	}
	pattern, found, err := a.ODB.SysrepSecurePatternByID(ctx, int64(id))
	if err != nil {
		log.Error("cannot read the secure pattern", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the secure pattern")
	}
	if !found {
		return JSONProblemf(c, http.StatusNotFound, "secure pattern %d does not exist", id)
	}
	if err := a.ODB.DeleteSysrepSecurePattern(ctx, int64(id)); err != nil {
		log.Error("cannot delete the secure pattern", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot delete the secure pattern")
	}
	a.logSysrep(ctx, c, log, "sysreport.secure_pattern.delete",
		"secure pattern %(s)s deleted", map[string]any{"s": pattern})
	return c.JSON(http.StatusOK, map[string]string{"info": "secure pattern " + pattern + " deleted"})
}

// GetSysreportAuthorizations handles GET /sysreport/authorizations.
func (a *Api) GetSysreportAuthorizations(c echo.Context, params server.GetSysreportAuthorizationsParams) error {
	if err := requireUserAuth(c); err != nil {
		return err
	}
	return a.handleList(c, "GetSysreportAuthorizations", "sysrep_allow", listEndpointParams{
		props: params.Props, limit: params.Limit, offset: params.Offset,
		meta: params.Meta, stats: params.Stats, orderby: params.Orderby, groupby: params.Groupby,
		filter: params.Filter,
	}, func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
		return a.ODB.GetSysrepAllows(ctx, p)
	})
}

// GetSysreportAuthorization handles GET /sysreport/authorizations/{id}.
func (a *Api) GetSysreportAuthorization(c echo.Context, id int, params server.GetSysreportAuthorizationParams) error {
	if err := requireUserAuth(c); err != nil {
		return err
	}
	return a.getSysreportAuthorization(c, "GetSysreportAuthorization", int64(id), params.Props)
}

func (a *Api) getSysreportAuthorization(c echo.Context, name string, id int64, props *server.InQueryProps) error {
	return a.handleItem(c, name, "sysrep_allow", "id", strconv.FormatInt(id, 10), listEndpointParams{props: props},
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetSysrepAllow(ctx, id, p)
		})
}

// sysrepAllowName names an authorization in the log as the historical
// collector did: group-filterset-pattern.
func sysrepAllowName(group, fset, pattern string) string {
	return strings.Join([]string{group, fset, pattern}, "-")
}

// resolveSysrepAllowInput returns the group and filterset an authorization
// request names, by id or by name. The error is meant for the client; the
// status says which.
func (a *Api) resolveSysrepAllowInput(ctx context.Context, body server.SysreportAuthorizationInput) (groupID int64, groupName string, fsetID int64, fsetName string, status int, err error) {
	switch {
	case body.GroupId != nil && body.GroupName != nil:
		return 0, "", 0, "", http.StatusBadRequest, errors.New("group_id and group_name are exclusive")
	case body.GroupId != nil:
		groupID = int64(*body.GroupId)
		var found bool
		if groupName, found, err = a.ODB.GroupRoleByID(ctx, groupID); err != nil {
			return 0, "", 0, "", http.StatusInternalServerError, err
		} else if !found {
			return 0, "", 0, "", http.StatusNotFound, fmt.Errorf("group %d does not exist", groupID)
		}
	case body.GroupName != nil:
		groupName = *body.GroupName
		var found bool
		if groupID, found, err = a.ODB.GroupIDByRole(ctx, groupName); err != nil {
			return 0, "", 0, "", http.StatusInternalServerError, err
		} else if !found {
			return 0, "", 0, "", http.StatusNotFound, fmt.Errorf("group %s does not exist", groupName)
		}
	default:
		return 0, "", 0, "", http.StatusBadRequest, errors.New("nor group_id nor group_name found in post data")
	}
	switch {
	case body.FsetId != nil && body.FsetName != nil:
		return 0, "", 0, "", http.StatusBadRequest, errors.New("fset_id and fset_name are exclusive")
	case body.FsetId != nil:
		fsetID = int64(*body.FsetId)
		var found bool
		if fsetName, found, err = a.ODB.FiltersetNameByID(ctx, fsetID); err != nil {
			return 0, "", 0, "", http.StatusInternalServerError, err
		} else if !found {
			return 0, "", 0, "", http.StatusNotFound, fmt.Errorf("filterset %d does not exist", fsetID)
		}
	case body.FsetName != nil:
		fsetName = *body.FsetName
		id, found, err := a.ODB.FiltersetByName(ctx, fsetName)
		if err != nil {
			return 0, "", 0, "", http.StatusInternalServerError, err
		} else if !found {
			return 0, "", 0, "", http.StatusNotFound, fmt.Errorf("filterset %s does not exist", fsetName)
		}
		fsetID = int64(id)
	default:
		return 0, "", 0, "", http.StatusBadRequest, errors.New("nor fset_id nor fset_name found in post data")
	}
	return groupID, groupName, fsetID, fsetName, 0, nil
}

// PostSysreportAuthorizations handles POST /sysreport/authorizations.
func (a *Api) PostSysreportAuthorizations(c echo.Context) error {
	log := echolog.GetLogHandler(c, "PostSysreportAuthorizations")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()
	if err := requireManager(c); err != nil {
		return err
	}
	var body server.PostSysreportAuthorizationsJSONRequestBody
	if err := c.Bind(&body); err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	pattern, err := checkSysrepPattern(&body.Pattern)
	if err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	groupID, groupName, fsetID, fsetName, status, err := a.resolveSysrepAllowInput(ctx, body)
	if err != nil {
		if status == http.StatusInternalServerError {
			log.Error("cannot check the authorization", logkey.Error, err)
			return JSONProblem(c, status, "cannot check the authorization")
		}
		return JSONProblem(c, status, err.Error())
	}
	if other, dup, err := a.ODB.SysrepAllowID(ctx, groupID, fsetID, pattern); err != nil {
		log.Error("cannot check duplicates", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot check duplicates")
	} else if dup {
		return JSONProblemf(c, http.StatusConflict, "authorization already exists: %d", other)
	}
	id, err := a.ODB.InsertSysrepAllow(ctx, groupID, fsetID, pattern)
	if err != nil {
		log.Error("cannot create the authorization", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot create the authorization")
	}
	a.logSysrep(ctx, c, log, "sysreport.authorization.create",
		"authorization %(s)s created.", map[string]any{"s": sysrepAllowName(groupName, fsetName, pattern)})
	return a.getSysreportAuthorization(c, "PostSysreportAuthorizations", id, nil)
}

// DeleteSysreportAuthorization handles DELETE /sysreport/authorizations/{id}.
func (a *Api) DeleteSysreportAuthorization(c echo.Context, id int) error {
	log := echolog.GetLogHandler(c, "DeleteSysreportAuthorization")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()
	if err := requireManager(c); err != nil {
		return err
	}
	row, err := a.ODB.SysrepAllowByID(ctx, int64(id))
	if err != nil {
		log.Error("cannot read the authorization", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot read the authorization")
	}
	if row == nil {
		return JSONProblemf(c, http.StatusNotFound, "authorization %d does not exist", id)
	}
	if err := a.ODB.DeleteSysrepAllow(ctx, row.ID); err != nil {
		log.Error("cannot delete the authorization", logkey.Error, err)
		return JSONProblem(c, http.StatusInternalServerError, "cannot delete the authorization")
	}
	group, fset := row.GroupName, row.FsetName
	if group == "" {
		group = strconv.FormatInt(row.GroupID, 10)
	}
	if fset == "" {
		fset = strconv.FormatInt(row.FsetID, 10)
	}
	name := sysrepAllowName(group, fset, row.Pattern)
	a.logSysrep(ctx, c, log, "sysreport.authorization.delete",
		"authorization %(s)s deleted", map[string]any{"s": name})
	return c.JSON(http.StatusOK, map[string]string{"info": "authorization " + name + " deleted"})
}
