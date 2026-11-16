package cdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// The administration of the declared networks, their segments and the groups
// responsible for those, as the historical collector's api_networks.py.

// GetNetwork returns the declared network id, as a list of one row or none.
func (oDb *DB) GetNetwork(ctx context.Context, id int, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "getNetwork", "networks", []string{"networks.id = ?"}, []any{id}, "networks.id", p)
}

// NetworkUpdate holds the properties of a network to change, nil when kept.
// An empty Gateway or Comment unsets it.
type NetworkUpdate struct {
	Name            *string
	Network         *string
	Netmask         *int
	Gateway         *string
	Comment         *string
	Pvid            *int
	Prio            *int
	TeamResponsible *string
}

// UpdateNetwork changes the properties u sets of the network id.
func (oDb *DB) UpdateNetwork(ctx context.Context, id int, u NetworkUpdate) error {
	var (
		sets []string
		args []any
	)
	set := func(col string, v any) {
		sets = append(sets, col+" = ?")
		args = append(args, v)
	}
	nullIfEmpty := func(s *string) any {
		if *s == "" {
			return nil
		}
		return *s
	}
	if u.Name != nil {
		set("name", nullIfEmpty(u.Name))
	}
	if u.Network != nil {
		set("network", *u.Network)
	}
	if u.Netmask != nil {
		set("netmask", *u.Netmask)
	}
	if u.Gateway != nil {
		set("gateway", nullIfEmpty(u.Gateway))
	}
	if u.Comment != nil {
		set("comment", nullIfEmpty(u.Comment))
	}
	if u.Pvid != nil {
		set("pvid", *u.Pvid)
	}
	if u.Prio != nil {
		set("prio", *u.Prio)
	}
	if u.TeamResponsible != nil {
		set("team_responsible", *u.TeamResponsible)
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, "updated = NOW()")
	args = append(args, id)
	if _, err := oDb.ExecContext(ctx, "UPDATE networks SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...); err != nil {
		return fmt.Errorf("UpdateNetwork: %w", err)
	}
	oDb.SetChange("networks")
	return nil
}

// NetworkSegmentOutside returns the id of a segment of the network netID not
// inside the begin–end range, if any.
func (oDb *DB) NetworkSegmentOutside(ctx context.Context, netID int, begin, end string) (int, bool, error) {
	var id int
	err := oDb.DB.QueryRowContext(ctx,
		`SELECT id FROM network_segments WHERE net_id = ?
		AND (INET_ATON(seg_begin) < INET_ATON(?) OR INET_ATON(seg_end) > INET_ATON(?)) LIMIT 1`,
		netID, begin, end).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("NetworkSegmentOutside: %w", err)
	}
	return id, true, nil
}

// DeleteNetwork deletes the network id, its segments and their responsible
// groups. It returns false when the network does not exist.
func (oDb *DB) DeleteNetwork(ctx context.Context, id int) (bool, error) {
	if _, err := oDb.ExecContext(ctx,
		"DELETE r FROM network_segment_responsibles r JOIN network_segments s ON s.id = r.seg_id WHERE s.net_id = ?", id); err != nil {
		return false, fmt.Errorf("DeleteNetwork: responsibles: %w", err)
	}
	if _, err := oDb.ExecContext(ctx, "DELETE FROM network_segments WHERE net_id = ?", id); err != nil {
		return false, fmt.Errorf("DeleteNetwork: segments: %w", err)
	}
	count, err := oDb.execCountContext(ctx, "DELETE FROM networks WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("DeleteNetwork: %w", err)
	}
	oDb.SetChange("networks", "network_segments", "network_segment_responsibles")
	return count > 0, nil
}

// GetNetworkSegments lists the segments of the network netID, by first address.
func (oDb *DB) GetNetworkSegments(ctx context.Context, netID int, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "getNetworkSegments", "network_segments", []string{"network_segments.net_id = ?"}, []any{netID},
		"INET_ATON(network_segments.seg_begin)", p)
}

// GetNetworkSegment returns the segment segID of the network netID, as a list
// of one row or none.
func (oDb *DB) GetNetworkSegment(ctx context.Context, netID, segID int, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "getNetworkSegment", "network_segments",
		[]string{"network_segments.net_id = ?", "network_segments.id = ?"}, []any{netID, segID}, "network_segments.id", p)
}

// NetworkSegment is a segment of a network.
type NetworkSegment struct {
	ID    int
	NetID int
	Type  string
	Begin string
	End   string
}

// GetNetworkSegmentOf returns the segment segID of the network netID.
func (oDb *DB) GetNetworkSegmentOf(ctx context.Context, netID, segID int) (NetworkSegment, bool, error) {
	s := NetworkSegment{ID: segID, NetID: netID}
	err := oDb.DB.QueryRowContext(ctx,
		`SELECT COALESCE(seg_type, ''), COALESCE(seg_begin, ''), COALESCE(seg_end, '')
		FROM network_segments WHERE id = ? AND net_id = ?`, segID, netID).Scan(&s.Type, &s.Begin, &s.End)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	if err != nil {
		return s, false, fmt.Errorf("GetNetworkSegmentOf: %w", err)
	}
	return s, true, nil
}

// NetworkSegmentOverlappingOther returns the id of a segment of the network,
// other than segID, sharing at least one address with begin–end, if any.
func (oDb *DB) NetworkSegmentOverlappingOther(ctx context.Context, netID, segID int, begin, end string) (int, bool, error) {
	var id int
	err := oDb.DB.QueryRowContext(ctx,
		`SELECT id FROM network_segments WHERE net_id = ? AND id != ?
		AND INET_ATON(seg_begin) <= INET_ATON(?) AND INET_ATON(seg_end) >= INET_ATON(?) LIMIT 1`,
		netID, segID, end, begin).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("NetworkSegmentOverlappingOther: %w", err)
	}
	return id, true, nil
}

// UpdateNetworkSegment sets the type and the range of the segment segID.
func (oDb *DB) UpdateNetworkSegment(ctx context.Context, segID int, segType, begin, end string) error {
	if _, err := oDb.ExecContext(ctx,
		"UPDATE network_segments SET seg_type = ?, seg_begin = ?, seg_end = ? WHERE id = ?",
		segType, begin, end, segID); err != nil {
		return fmt.Errorf("UpdateNetworkSegment: %w", err)
	}
	oDb.SetChange("network_segments")
	return nil
}

// DeleteNetworkSegment deletes the segment segID and its responsible groups.
func (oDb *DB) DeleteNetworkSegment(ctx context.Context, segID int) error {
	if _, err := oDb.ExecContext(ctx, "DELETE FROM network_segment_responsibles WHERE seg_id = ?", segID); err != nil {
		return fmt.Errorf("DeleteNetworkSegment: responsibles: %w", err)
	}
	if _, err := oDb.ExecContext(ctx, "DELETE FROM network_segments WHERE id = ?", segID); err != nil {
		return fmt.Errorf("DeleteNetworkSegment: %w", err)
	}
	oDb.SetChange("network_segments", "network_segment_responsibles")
	return nil
}

const networkSegmentResponsiblesFrom = "network_segment_responsibles JOIN auth_group ON auth_group.id = network_segment_responsibles.group_id"

// GetNetworkSegmentResponsibles lists the groups responsible for the segment
// segID, by name.
func (oDb *DB) GetNetworkSegmentResponsibles(ctx context.Context, segID int, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "getNetworkSegmentResponsibles", networkSegmentResponsiblesFrom,
		[]string{"network_segment_responsibles.seg_id = ?"}, []any{segID}, "auth_group.role", p)
}

// GetNetworkSegmentResponsible returns the responsibility of the group groupID
// for the segment segID, as a list of one row or none.
func (oDb *DB) GetNetworkSegmentResponsible(ctx context.Context, segID int, groupID int64, p ListParams) ([]map[string]any, error) {
	return oDb.listQuery(ctx, "getNetworkSegmentResponsible", networkSegmentResponsiblesFrom,
		[]string{"network_segment_responsibles.seg_id = ?", "network_segment_responsibles.group_id = ?"}, []any{segID, groupID},
		"auth_group.role", p)
}

// NetworkSegmentHasResponsible tells if one of the groupIDs is responsible
// for the segment segID.
func (oDb *DB) NetworkSegmentHasResponsible(ctx context.Context, segID int, groupIDs []int64) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}
	args := []any{segID}
	for _, id := range groupIDs {
		args = append(args, id)
	}
	var n int
	err := oDb.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM network_segment_responsibles WHERE seg_id = ? AND group_id IN ("+Placeholders(len(groupIDs))+")",
		args...).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("NetworkSegmentHasResponsible: %w", err)
	}
	return n > 0, nil
}

// AddNetworkSegmentResponsible makes the group groupID responsible for the
// segment segID. It returns false when it already was.
func (oDb *DB) AddNetworkSegmentResponsible(ctx context.Context, segID int, groupID int64) (bool, error) {
	if ok, err := oDb.NetworkSegmentHasResponsible(ctx, segID, []int64{groupID}); err != nil {
		return false, err
	} else if ok {
		return false, nil
	}
	if _, err := oDb.ExecContext(ctx,
		"INSERT INTO network_segment_responsibles (seg_id, group_id) VALUES (?, ?)", segID, groupID); err != nil {
		return false, fmt.Errorf("AddNetworkSegmentResponsible: %w", err)
	}
	oDb.SetChange("network_segment_responsibles")
	return true, nil
}

// RemoveNetworkSegmentResponsible detaches the group groupID from the segment
// segID. It returns false when it was not responsible.
func (oDb *DB) RemoveNetworkSegmentResponsible(ctx context.Context, segID int, groupID int64) (bool, error) {
	count, err := oDb.execCountContext(ctx,
		"DELETE FROM network_segment_responsibles WHERE seg_id = ? AND group_id = ?", segID, groupID)
	if err != nil {
		return false, fmt.Errorf("RemoveNetworkSegmentResponsible: %w", err)
	}
	if count > 0 {
		oDb.SetChange("network_segment_responsibles")
	}
	return count > 0, nil
}

// GetNetworkSegmentsOf returns the segments of the network netID, by first
// address, those one of groupIDs is responsible for only unless all.
func (oDb *DB) GetNetworkSegmentsOf(ctx context.Context, netID int, all bool, groupIDs []int64) ([]NetworkSegment, error) {
	query := `SELECT s.id, COALESCE(s.seg_type, ''), COALESCE(s.seg_begin, ''), COALESCE(s.seg_end, '')
		FROM network_segments s WHERE s.net_id = ?`
	args := []any{netID}
	if !all {
		if len(groupIDs) == 0 {
			return nil, nil
		}
		query += " AND EXISTS (SELECT 1 FROM network_segment_responsibles r WHERE r.seg_id = s.id AND r.group_id IN (" +
			Placeholders(len(groupIDs)) + "))"
		for _, id := range groupIDs {
			args = append(args, id)
		}
	}
	query += " ORDER BY INET_ATON(s.seg_begin)"
	rows, err := oDb.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("GetNetworkSegmentsOf: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var l []NetworkSegment
	for rows.Next() {
		s := NetworkSegment{NetID: netID}
		if err := rows.Scan(&s.ID, &s.Type, &s.Begin, &s.End); err != nil {
			return nil, fmt.Errorf("GetNetworkSegmentsOf: %w", err)
		}
		l = append(l, s)
	}
	return l, rows.Err()
}

// CountNetworkSegments returns the count of the segments of the network netID.
func (oDb *DB) CountNetworkSegments(ctx context.Context, netID int) (int, error) {
	var n int
	if err := oDb.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_segments WHERE net_id = ?", netID).Scan(&n); err != nil {
		return 0, fmt.Errorf("CountNetworkSegments: %w", err)
	}
	return n, nil
}

// NodeAddress is a node reporting an address.
type NodeAddress struct {
	Addr     string
	NodeID   string
	Nodename string
}

// NodeAddressesBetween returns the node addresses from begin to end, IPv4.
func (oDb *DB) NodeAddressesBetween(ctx context.Context, begin, end string) ([]NodeAddress, error) {
	rows, err := oDb.DB.QueryContext(ctx,
		`SELECT DISTINCT ni.addr, ni.node_id, COALESCE(n.nodename, '')
		FROM node_ip ni LEFT JOIN nodes n ON n.node_id = ni.node_id
		WHERE INET_ATON(ni.addr) BETWEEN INET_ATON(?) AND INET_ATON(?)
		ORDER BY n.nodename`, begin, end)
	if err != nil {
		return nil, fmt.Errorf("NodeAddressesBetween: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var l []NodeAddress
	for rows.Next() {
		var a NodeAddress
		if err := rows.Scan(&a.Addr, &a.NodeID, &a.Nodename); err != nil {
			return nil, fmt.Errorf("NodeAddressesBetween: %w", err)
		}
		l = append(l, a)
	}
	return l, rows.Err()
}
