package serverhandlers

import (
	"context"
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

// The OpenID Connect identities linked to the accounts. A browser sign-in links
// its identity by itself; an automation signing in with access tokens only, a
// service account of the provider, needs its identity linked by an
// administrator: a Bearer token never creates nor links an account.

// identityTarget resolves the account userId names, visible to the caller.
func (a *Api) identityTarget(ctx context.Context, c echo.Context, log *slog.Logger, userId string) (int64, error) {
	selfID := authUserID(c)
	if selfID == nil {
		return 0, httpErrorf(http.StatusUnauthorized, "user authentication required")
	}
	targetID, found, err := a.ODB.UserIDForPrefs(ctx, userId, cdb.ListParams{
		Groups: UserGroupsFromContext(c), IsManager: IsManager(c), UserID: selfID,
	})
	if err != nil {
		return 0, httpInternal(log, "cannot resolve the user", err)
	}
	if !found {
		return 0, httpErrorf(http.StatusNotFound, "user %s not found", userId)
	}
	return targetID, nil
}

// identityWriteTarget resolves the account whose identities the caller changes:
// a UserManager, and a Manager for the account of a Manager, whose privileges
// the identity would take.
func (a *Api) identityWriteTarget(ctx context.Context, c echo.Context, log *slog.Logger, userId string) (int64, string, error) {
	targetID, err := a.identityTarget(ctx, c, log, userId)
	if err != nil {
		return 0, "", err
	}
	isTargetManager, err := a.ODB.UserInRole(ctx, targetID, "Manager")
	if err != nil {
		return 0, "", httpInternal(log, "cannot read the teams of the user", err)
	}
	if isTargetManager && !IsManager(c) {
		return 0, "", httpErrorf(http.StatusForbidden, "only a Manager may change the identities of a Manager")
	}
	user, found, err := a.ODB.GetUserIdentity(ctx, targetID)
	if err != nil {
		return 0, "", httpInternal(log, "cannot read the user", err)
	}
	if !found {
		return 0, "", httpErrorf(http.StatusNotFound, "user %s not found", userId)
	}
	return targetID, user.Email, nil
}

// GetUserIdentities handles GET /users/{user_id}/identities.
func (a *Api) GetUserIdentities(c echo.Context, userId string, params server.GetUserIdentitiesParams) error {
	log := echolog.GetLogHandler(c, "GetUserIdentities")
	ctx := c.Request().Context()
	if !IsAuthByUser(c) {
		return denyRequest(c, http.StatusUnauthorized, "user authentication required")
	}
	targetID, err := a.identityTarget(ctx, c, log, userId)
	if err != nil {
		return httpProblem(c, err)
	}
	if selfID := authUserID(c); !IsUserManager(c) && (selfID == nil || *selfID != targetID) {
		return denyRequest(c, http.StatusForbidden, "UserManager privilege required")
	}
	return a.handleList(c, "GetUserIdentities", "user_identity",
		listParams(params.Props, params.Limit, params.Offset, params.Meta, params.Stats, params.Orderby, params.Groupby, params.Filter),
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetUserOIDCIdentities(ctx, targetID, p)
		})
}

// PostUserIdentities handles POST /users/{user_id}/identities: link an identity
// of the collector's provider to an account.
func (a *Api) PostUserIdentities(c echo.Context, userId string) error {
	log := echolog.GetLogHandler(c, "PostUserIdentities")
	odb := a.ODB
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireUserManager(c); err != nil {
		return err
	}
	var body server.PostUserIdentitiesJSONRequestBody
	if err := c.Bind(&body); err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	if a.OIDC == nil || a.OIDC.Config().Issuer == "" {
		return JSONProblemf(c, http.StatusConflict, "no OpenID Connect provider is configured on this collector")
	}
	providerIssuer := a.OIDC.Config().Issuer
	subject := strings.TrimSpace(body.Subject)
	if subject == "" || len(subject) > 255 {
		return JSONProblemf(c, http.StatusBadRequest, "subject must be the sub claim of the identity's tokens, 1 to 255 characters")
	}
	issuer := providerIssuer
	if body.Issuer != nil && strings.TrimSpace(*body.Issuer) != "" {
		issuer = strings.TrimSpace(*body.Issuer)
	}
	// Only the tokens of the configured provider are verified: an identity of
	// another issuer would never sign in.
	if issuer != providerIssuer {
		return JSONProblemf(c, http.StatusBadRequest, "issuer must be the one of the collector's provider, %s, got %s", providerIssuer, issuer)
	}
	targetID, email, err := a.identityWriteTarget(ctx, c, log, userId)
	if err != nil {
		return httpProblem(c, err)
	}
	if _, otherID, linked, err := odb.OIDCIdentityID(ctx, issuer, subject); err != nil {
		return httpProblem(c, httpInternal(log, "cannot check the identity", err))
	} else if linked {
		return JSONProblemf(c, http.StatusConflict, "this identity is already linked to user %d", otherID)
	}
	// One identity per account: replacing it takes unlinking it first.
	if has, err := odb.UserHasIdentity(ctx, targetID); err != nil {
		return httpProblem(c, httpInternal(log, "cannot check the identities of the user", err))
	} else if has {
		return JSONProblemf(c, http.StatusConflict, "user %d already has an identity linked: unlink it first", targetID)
	}

	log.Info("called", "user_id", targetID, "iss", issuer, "sub", subject)
	if err := odb.LinkIdentity(ctx, targetID, issuer, subject); err != nil {
		return httpProblem(c, httpInternal(log, "cannot link the identity", err))
	}
	a.logUserIdentityAction(ctx, c, log, "users.identity.link", "linked the identity %(sub)s of %(iss)s to %(email)s",
		map[string]any{"email": email, "iss": issuer, "sub": subject})

	id, _, _, err := odb.OIDCIdentityID(ctx, issuer, subject)
	if err == nil {
		var rows []map[string]any
		if rows, err = a.identityRows(ctx, targetID, id); err == nil {
			return c.JSON(http.StatusOK, map[string]any{"data": rows, "info": fmt.Sprintf("identity linked to user %d", targetID)})
		}
	}
	log.Error("cannot read the linked identity", logkey.Error, err)
	return JSONProblemf(c, http.StatusInternalServerError, "identity linked but cannot be read back")
}

func (a *Api) identityRows(ctx context.Context, userID, id int64) ([]map[string]any, error) {
	mapping := propsMapping["user_identity"]
	query, err := buildListQueryParameters(nil, nil, nil, nil, nil, nil, nil, mapping)
	if err != nil {
		return nil, err
	}
	selectExprs, err := buildSelectClause(query.Props, mapping)
	if err != nil {
		return nil, err
	}
	return a.ODB.GetUserOIDCIdentity(ctx, userID, id, cdb.ListParams{
		IsManager: true, Props: query.Props, SelectExprs: selectExprs, TypeHints: buildTypeHints(query.Props, mapping),
	})
}

// DeleteUserIdentity handles DELETE /users/{user_id}/identities/{identity_id}.
func (a *Api) DeleteUserIdentity(c echo.Context, userId string, identityId string) error {
	log := echolog.GetLogHandler(c, "DeleteUserIdentity")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireUserManager(c); err != nil {
		return err
	}
	id, err := strconv.ParseInt(identityId, 10, 64)
	if err != nil || id <= 0 {
		return JSONProblemf(c, http.StatusBadRequest, "identity id must be a positive integer, got %q", identityId)
	}
	targetID, email, err := a.identityWriteTarget(ctx, c, log, userId)
	if err != nil {
		return httpProblem(c, err)
	}
	log.Info("called", "user_id", targetID, "identity_id", id)
	issuer, subject, found, err := a.ODB.UnlinkOIDCIdentity(ctx, targetID, id)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot unlink the identity", err))
	}
	if !found {
		return JSONProblemf(c, http.StatusNotFound, "identity %d of user %d not found", id, targetID)
	}
	a.logUserIdentityAction(ctx, c, log, "users.identity.unlink", "unlinked the identity %(sub)s of %(iss)s from %(email)s",
		map[string]any{"email": email, "iss": issuer, "sub": subject})
	return c.JSON(http.StatusOK, map[string]any{"info": fmt.Sprintf("identity %d unlinked from user %d", id, targetID)})
}

func (a *Api) logUserIdentityAction(ctx context.Context, c echo.Context, log *slog.Logger, action, format string, dict map[string]any) {
	userEmail, _ := c.Get(XUserEmail).(string)
	if err := a.ODB.Log(ctx, cdb.LogEntry{Action: action, User: userEmail, Fmt: format, Dict: dict, Level: "info"}); err != nil {
		log.Error("cannot write audit log", logkey.Error, err)
	}
	if err := a.ODB.Session.NotifyChanges(ctx); err != nil {
		log.Error("cannot notify changes", logkey.Error, err)
	}
}
