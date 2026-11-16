package cdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// sysrepAllowFrom is the FROM clause of the sysreport authorization lists: a
// derived table named after sysrep_allow, where each authorization carries the
// name of its group and of its filterset, as the historical collector's
// v_sysrep_allow view did, so that they can be selected, filtered and sorted
// like the other columns.
const sysrepAllowFrom = `(
	SELECT a.id, a.pattern, a.fset_id, a.group_id,
		g.role AS group_name, fs.fset_name
	FROM sysrep_allow a
	LEFT JOIN auth_group g ON g.id = a.group_id
	LEFT JOIN gen_filtersets fs ON fs.id = a.fset_id
) sysrep_allow`

// GetSysrepSecurePatterns lists the sysreport secure patterns.
func (oDb *DB) GetSysrepSecurePatterns(ctx context.Context, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "GetSysrepSecurePatterns", "sysrep_secure", []string{"sysrep_secure.id > 0"}, nil,
		"sysrep_secure.pattern, sysrep_secure.id", p)
}

// GetSysrepSecurePattern returns one sysreport secure pattern.
func (oDb *DB) GetSysrepSecurePattern(ctx context.Context, id int64, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "GetSysrepSecurePattern", "sysrep_secure", []string{"sysrep_secure.id = ?"}, []any{id},
		"sysrep_secure.id", p)
}

// SysrepSecurePatternByID returns the pattern of a secure pattern, and whether
// there is one with this id.
func (oDb *DB) SysrepSecurePatternByID(ctx context.Context, id int64) (string, bool, error) {
	var pattern string
	err := oDb.DB.QueryRowContext(ctx, "SELECT pattern FROM sysrep_secure WHERE id = ?", id).Scan(&pattern)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("SysrepSecurePatternByID: %w", err)
	}
	return pattern, true, nil
}

// SysrepSecurePatternID returns the id of the secure pattern exactly equal to
// pattern, case included, and whether there is one.
func (oDb *DB) SysrepSecurePatternID(ctx context.Context, pattern string) (int64, bool, error) {
	var id int64
	err := oDb.DB.QueryRowContext(ctx,
		"SELECT id FROM sysrep_secure WHERE CAST(pattern AS BINARY) = CAST(? AS BINARY) LIMIT 1", pattern).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("SysrepSecurePatternID: %w", err)
	}
	return id, true, nil
}

// InsertSysrepSecurePattern creates a secure pattern and returns its id.
func (oDb *DB) InsertSysrepSecurePattern(ctx context.Context, pattern string) (int64, error) {
	res, err := oDb.ExecContext(ctx, "INSERT INTO sysrep_secure (pattern) VALUES (?)", pattern)
	if err != nil {
		return 0, fmt.Errorf("InsertSysrepSecurePattern: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("InsertSysrepSecurePattern lastInsertId: %w", err)
	}
	oDb.SetChange("sysrep_secure")
	return id, nil
}

// DeleteSysrepSecurePattern deletes a secure pattern.
func (oDb *DB) DeleteSysrepSecurePattern(ctx context.Context, id int64) error {
	if _, err := oDb.ExecContext(ctx, "DELETE FROM sysrep_secure WHERE id = ?", id); err != nil {
		return fmt.Errorf("DeleteSysrepSecurePattern: %w", err)
	}
	oDb.SetChange("sysrep_secure")
	return nil
}

// GetSysrepAllows lists the sysreport authorizations, with the names of their
// group and filterset.
func (oDb *DB) GetSysrepAllows(ctx context.Context, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "GetSysrepAllows", sysrepAllowFrom, []string{"sysrep_allow.id > 0"}, nil,
		"sysrep_allow.group_name, sysrep_allow.fset_name, sysrep_allow.pattern, sysrep_allow.id", p)
}

// GetSysrepAllow returns one sysreport authorization.
func (oDb *DB) GetSysrepAllow(ctx context.Context, id int64, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "GetSysrepAllow", sysrepAllowFrom, []string{"sysrep_allow.id = ?"}, []any{id},
		"sysrep_allow.id", p)
}

// SysrepAllowRow is a sysreport authorization, with the names of its group and
// filterset, empty when they do not exist any more.
type SysrepAllowRow struct {
	ID        int64
	Pattern   string
	FsetID    int64
	GroupID   int64
	FsetName  string
	GroupName string
}

// SysrepAllowByID returns an authorization, nil when there is none with this id.
func (oDb *DB) SysrepAllowByID(ctx context.Context, id int64) (*SysrepAllowRow, error) {
	var (
		r         SysrepAllowRow
		group     sql.NullString
		filterset sql.NullString
	)
	err := oDb.DB.QueryRowContext(ctx,
		"SELECT id, pattern, fset_id, group_id, group_name, fset_name FROM "+sysrepAllowFrom+" WHERE sysrep_allow.id = ?", id).
		Scan(&r.ID, &r.Pattern, &r.FsetID, &r.GroupID, &group, &filterset)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("SysrepAllowByID: %w", err)
	}
	r.GroupName, r.FsetName = group.String, filterset.String
	return &r, nil
}

// SysrepAllowID returns the id of the authorization of the group on the
// filterset for exactly pattern, case included, and whether there is one.
func (oDb *DB) SysrepAllowID(ctx context.Context, groupID, fsetID int64, pattern string) (int64, bool, error) {
	var id int64
	err := oDb.DB.QueryRowContext(ctx,
		`SELECT id FROM sysrep_allow
		WHERE group_id = ? AND fset_id = ? AND CAST(pattern AS BINARY) = CAST(? AS BINARY) LIMIT 1`,
		groupID, fsetID, pattern).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("SysrepAllowID: %w", err)
	}
	return id, true, nil
}

// InsertSysrepAllow creates an authorization and returns its id.
func (oDb *DB) InsertSysrepAllow(ctx context.Context, groupID, fsetID int64, pattern string) (int64, error) {
	res, err := oDb.ExecContext(ctx,
		"INSERT INTO sysrep_allow (group_id, fset_id, pattern) VALUES (?, ?, ?)", groupID, fsetID, pattern)
	if err != nil {
		return 0, fmt.Errorf("InsertSysrepAllow: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("InsertSysrepAllow lastInsertId: %w", err)
	}
	oDb.SetChange("sysrep_allow")
	return id, nil
}

// DeleteSysrepAllow deletes an authorization.
func (oDb *DB) DeleteSysrepAllow(ctx context.Context, id int64) error {
	if _, err := oDb.ExecContext(ctx, "DELETE FROM sysrep_allow WHERE id = ?", id); err != nil {
		return fmt.Errorf("DeleteSysrepAllow: %w", err)
	}
	oDb.SetChange("sysrep_allow")
	return nil
}

// FiltersetNameByID returns the name of a filterset, and whether it exists.
func (oDb *DB) FiltersetNameByID(ctx context.Context, id int64) (string, bool, error) {
	var name sql.NullString
	err := oDb.DB.QueryRowContext(ctx, "SELECT fset_name FROM gen_filtersets WHERE id = ?", id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("FiltersetNameByID: %w", err)
	}
	return name.String, true, nil
}
