package serverhandlers

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/opensvc/oc3/cdb"
	"github.com/opensvc/oc3/server"
	"github.com/opensvc/oc3/util/echolog"
	"github.com/opensvc/oc3/util/logkey"
)

// The administration of the declared networks, their segments and the groups
// responsible for those, as the historical collector's api_networks.py. The
// allocation and the release of addresses, which wrote DNS records, are not
// ported.

// maxNetworkIps bounds the addresses GET /networks/{net_id}/ips lists: a /16.
const maxNetworkIps = 1 << 16

func parseRecordID(name, value string) (int, error) {
	id, err := strconv.Atoi(value)
	if err != nil || id <= 0 {
		return 0, httpErrorf(http.StatusBadRequest, "%s must be a positive integer, got %q", name, value)
	}
	return id, nil
}

// networkForWrite returns the network netID the caller may change: a manager,
// or a member of its responsible team.
func (a *Api) networkForWrite(ctx context.Context, c echo.Context, log *slog.Logger, netID int) (cdb.NetworkRange, error) {
	network, found, err := a.ODB.GetNetworkRange(ctx, netID)
	if err != nil {
		return network, httpInternal(log, "cannot read network", err)
	}
	if !found {
		return network, httpErrorf(http.StatusNotFound, "network %d not found", netID)
	}
	if !IsManager(c) && !slices.Contains(UserGroupsFromContext(c), network.TeamResponsible) {
		return network, httpErrorf(http.StatusForbidden, "not responsible for network %d", netID)
	}
	return network, nil
}

// segmentForWrite returns the segment segID of the network netID the caller
// may change: a manager, a member of a group responsible for the segment or of
// the team responsible for the network.
func (a *Api) segmentForWrite(ctx context.Context, c echo.Context, log *slog.Logger, netID, segID int) (cdb.NetworkRange, cdb.NetworkSegment, error) {
	odb := a.ODB
	var segment cdb.NetworkSegment
	network, found, err := odb.GetNetworkRange(ctx, netID)
	if err != nil {
		return network, segment, httpInternal(log, "cannot read network", err)
	}
	if !found {
		return network, segment, httpErrorf(http.StatusNotFound, "network %d not found", netID)
	}
	segment, found, err = odb.GetNetworkSegmentOf(ctx, netID, segID)
	if err != nil {
		return network, segment, httpInternal(log, "cannot read segment", err)
	}
	if !found {
		return network, segment, httpErrorf(http.StatusNotFound, "segment %d of network %d not found", segID, netID)
	}
	if IsManager(c) || slices.Contains(UserGroupsFromContext(c), network.TeamResponsible) {
		return network, segment, nil
	}
	userID := authUserID(c)
	if userID == nil {
		return network, segment, httpErrorf(http.StatusForbidden, "not responsible for segment %d", segID)
	}
	groupIDs, err := odb.UserGroupIDs(ctx, *userID)
	if err != nil {
		return network, segment, httpInternal(log, "cannot get the groups of the user", err)
	}
	ok, err := odb.NetworkSegmentHasResponsible(ctx, segID, groupIDs)
	if err != nil {
		return network, segment, httpInternal(log, "cannot check segment responsibles", err)
	}
	if !ok {
		return network, segment, httpErrorf(http.StatusForbidden, "not responsible for segment %d", segID)
	}
	return network, segment, nil
}

func (a *Api) logNetworkAction(ctx context.Context, c echo.Context, log *slog.Logger, action, format string, dict map[string]any) {
	userEmail, _ := c.Get(XUserEmail).(string)
	if err := a.ODB.Log(ctx, cdb.LogEntry{Action: action, User: userEmail, Fmt: format, Dict: dict, Level: "info"}); err != nil {
		log.Error("cannot write audit log", logkey.Error, err)
	}
	if err := a.ODB.Session.NotifyChanges(ctx); err != nil {
		log.Error("cannot notify changes", logkey.Error, err)
	}
}

func segmentLabel(s cdb.NetworkSegment) string { return s.Begin + "-" + s.End }

func networkLabel(n cdb.NetworkRange) string { return fmt.Sprintf("%s/%d", n.Network, n.Netmask) }

// GetNetwork handles GET /networks/{net_id}.
func (a *Api) GetNetwork(c echo.Context, netId string, params server.GetNetworkParams) error {
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	return a.handleItem(c, "GetNetwork", "network", "net_id", netId,
		listParams(params.Props, params.Limit, params.Offset, params.Meta, params.Stats, params.Orderby, params.Groupby, params.Filter),
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetNetwork(ctx, netID, p)
		})
}

// PostNetwork handles POST /networks/{net_id}: change the properties of a
// network, as the historical collector's rest_post_network did.
func (a *Api) PostNetwork(c echo.Context, netId string) error {
	log := echolog.GetLogHandler(c, "PostNetwork")
	odb := a.ODB
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireNetworkManager(c); err != nil {
		return err
	}
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	var body server.PostNetworkJSONRequestBody
	if err := c.Bind(&body); err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	current, err := a.networkForWrite(ctx, c, log, netID)
	if err != nil {
		return httpProblem(c, err)
	}

	u := cdb.NetworkUpdate{Comment: body.Comment}

	// The address and the mask, changed together or not, make the new prefix.
	address, netmask := current.Network, current.Netmask
	if body.Network != nil {
		address = strings.TrimSpace(*body.Network)
	}
	if body.Netmask != nil {
		netmask = *body.Netmask
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() {
		return JSONProblemf(c, http.StatusBadRequest, "network must be an IPv4 address, got %q", address)
	}
	if netmask < 0 || netmask > 32 {
		return JSONProblemf(c, http.StatusBadRequest, "netmask must be a prefix length between 0 and 32")
	}
	prefix := netip.PrefixFrom(addr, netmask)
	if masked := prefix.Masked(); masked.Addr() != addr {
		return JSONProblemf(c, http.StatusBadRequest, "%s is not a network address, did you mean %s?", prefix, masked)
	}
	if addr.String() != current.Network || netmask != current.Netmask {
		otherID, taken, err := odb.NetworkIDByAddress(ctx, addr.String(), netmask)
		if err != nil {
			return httpProblem(c, httpInternal(log, "cannot check network address", err))
		}
		if taken && otherID != netID {
			return JSONProblemf(c, http.StatusConflict, "network %s is already declared: %d", prefix, otherID)
		}
		begin, end := prefixUsableRange(prefix)
		if segID, outside, err := odb.NetworkSegmentOutside(ctx, netID, begin.String(), end.String()); err != nil {
			return httpProblem(c, httpInternal(log, "cannot check the segments", err))
		} else if outside {
			return JSONProblemf(c, http.StatusConflict, "segment %d would be outside %s", segID, prefix)
		}
		s := addr.String()
		u.Network, u.Netmask = &s, &netmask
	}

	if body.Gateway != nil {
		gateway := strings.TrimSpace(*body.Gateway)
		if gateway != "" {
			gw, err := netip.ParseAddr(gateway)
			if err != nil || !gw.Is4() || !prefix.Contains(gw) {
				return JSONProblemf(c, http.StatusBadRequest, "gateway must be an IPv4 address inside %s", prefix)
			}
			gateway = gw.String()
		}
		u.Gateway = &gateway
	}
	if body.Prio != nil {
		if *body.Prio < 0 || *body.Prio > 99 {
			return JSONProblemf(c, http.StatusBadRequest, "prio must be between 0 and 99")
		}
		u.Prio = body.Prio
	}
	if body.Pvid != nil {
		if *body.Pvid < 0 || *body.Pvid > 4094 {
			return JSONProblemf(c, http.StatusBadRequest, "pvid must be a VLAN id between 0 and 4094")
		}
		u.Pvid = body.Pvid
	}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name != "" {
			otherID, taken, err := odb.NetworkIDByName(ctx, name)
			if err != nil {
				return httpProblem(c, httpInternal(log, "cannot check network name", err))
			}
			if taken && otherID != netID {
				return JSONProblemf(c, http.StatusConflict, "a network named %s already exists: %d", name, otherID)
			}
		}
		u.Name = &name
	}
	if body.TeamResponsible != nil {
		team := strings.TrimSpace(*body.TeamResponsible)
		ok, err := odb.IsAssignableTeam(ctx, team)
		if err != nil {
			return httpProblem(c, httpInternal(log, "cannot check team", err))
		}
		if !ok {
			return JSONProblemf(c, http.StatusBadRequest, "team_responsible must be an existing organisational group, got %q", team)
		}
		u.TeamResponsible = &team
	}

	log.Info("called", "net_id", netID)
	if err := odb.UpdateNetwork(ctx, netID, u); err != nil {
		return httpProblem(c, httpInternal(log, "cannot update network", err))
	}
	a.logNetworkAction(ctx, c, log, "networks.update", "updated network %(network)s", map[string]any{"network": prefix.String()})

	row, err := odb.GetNetworkRow(ctx, netID)
	if err != nil || row == nil {
		log.Error("cannot read the updated network", "id", netID, logkey.Error, err)
		return JSONProblemf(c, http.StatusInternalServerError, "network %d updated but cannot be read back", netID)
	}
	return c.JSON(http.StatusOK, map[string]any{"data": []any{row}, "info": fmt.Sprintf("network %d updated", netID)})
}

// prefixUsableRange returns the first and the last address of the prefix a
// segment may use, as the begin and end columns of networks compute them: the
// network and the broadcast addresses left out.
func prefixUsableRange(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	network := prefix.Masked().Addr()
	b := network.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	size := uint64(1) << (32 - prefix.Bits())
	if size <= 2 {
		// /31 and /32: no network nor broadcast address to leave out.
		return u32Addr(n), u32Addr(uint32(uint64(n) + size - 1))
	}
	first := n + 1
	last := uint32(uint64(n) + size - 2)
	return u32Addr(first), u32Addr(last)
}

func u32Addr(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// DeleteNetwork handles DELETE /networks/{net_id}.
func (a *Api) DeleteNetwork(c echo.Context, netId string) error {
	log := echolog.GetLogHandler(c, "DeleteNetwork")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireNetworkManager(c); err != nil {
		return err
	}
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	network, err := a.networkForWrite(ctx, c, log, netID)
	if err != nil {
		return httpProblem(c, err)
	}
	log.Info("called", "net_id", netID)
	if _, err := a.ODB.DeleteNetwork(ctx, netID); err != nil {
		return httpProblem(c, httpInternal(log, "cannot delete network", err))
	}
	a.logNetworkAction(ctx, c, log, "networks.delete", "deleted network %(network)s", map[string]any{"network": networkLabel(network)})
	return c.JSON(http.StatusOK, map[string]any{"info": fmt.Sprintf("network %s deleted", networkLabel(network))})
}

// GetNetworkSegments handles GET /networks/{net_id}/segments.
func (a *Api) GetNetworkSegments(c echo.Context, netId string, params server.GetNetworkSegmentsParams) error {
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	if _, found, err := a.ODB.GetNetworkRange(c.Request().Context(), netID); err != nil {
		return httpProblem(c, httpInternal(echolog.GetLogHandler(c, "GetNetworkSegments"), "cannot read network", err))
	} else if !found {
		return JSONProblemf(c, http.StatusNotFound, "network %d not found", netID)
	}
	return a.handleList(c, "GetNetworkSegments", "network_segment",
		listParams(params.Props, params.Limit, params.Offset, params.Meta, params.Stats, params.Orderby, params.Groupby, params.Filter),
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetNetworkSegments(ctx, netID, p)
		})
}

// GetNetworkSegment handles GET /networks/{net_id}/segments/{seg_id}.
func (a *Api) GetNetworkSegment(c echo.Context, netId string, segId string, params server.GetNetworkSegmentParams) error {
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	segID, err := parseRecordID("segment id", segId)
	if err != nil {
		return httpProblem(c, err)
	}
	return a.handleItem(c, "GetNetworkSegment", "network_segment", "seg_id", segId,
		listParams(params.Props, params.Limit, params.Offset, params.Meta, params.Stats, params.Orderby, params.Groupby, params.Filter),
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetNetworkSegment(ctx, netID, segID, p)
		})
}

// PostNetworkSegment handles POST /networks/{net_id}/segments/{seg_id}: change
// the type or the range of a segment.
func (a *Api) PostNetworkSegment(c echo.Context, netId string, segId string) error {
	log := echolog.GetLogHandler(c, "PostNetworkSegment")
	odb := a.ODB
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireNetworkManager(c); err != nil {
		return err
	}
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	segID, err := parseRecordID("segment id", segId)
	if err != nil {
		return httpProblem(c, err)
	}
	var body server.PostNetworkSegmentJSONRequestBody
	if err := c.Bind(&body); err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	network, segment, err := a.segmentForWrite(ctx, c, log, netID, segID)
	if err != nil {
		return httpProblem(c, err)
	}

	segType := segment.Type
	if body.SegType != nil && *body.SegType != "" {
		segType = string(*body.SegType)
	}
	if segType != "static" && segType != "dynamic" {
		return JSONProblemf(c, http.StatusBadRequest, "seg_type must be static or dynamic, got %q", segType)
	}
	netBegin, errB := netip.ParseAddr(network.Begin)
	netEnd, errE := netip.ParseAddr(network.End)
	if errB != nil || errE != nil {
		return JSONProblemf(c, http.StatusConflict, "network %d has no usable range", netID)
	}
	parse := func(name, value string) (netip.Addr, error) {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.Is4() {
			return addr, fmt.Errorf("%s must be an IPv4 address, got %q", name, value)
		}
		if addr.Less(netBegin) || netEnd.Less(addr) {
			return addr, fmt.Errorf("%s %s is outside the network range %s - %s", name, addr, netBegin, netEnd)
		}
		return addr, nil
	}
	beginValue, endValue := segment.Begin, segment.End
	if body.SegBegin != nil {
		beginValue = *body.SegBegin
	}
	if body.SegEnd != nil {
		endValue = *body.SegEnd
	}
	begin, err := parse("seg_begin", beginValue)
	if err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	end, err := parse("seg_end", endValue)
	if err != nil {
		return JSONProblem(c, http.StatusBadRequest, err.Error())
	}
	if end.Less(begin) {
		return JSONProblemf(c, http.StatusBadRequest, "seg_end %s is before seg_begin %s", end, begin)
	}
	if otherID, taken, err := odb.NetworkSegmentOverlappingOther(ctx, netID, segID, begin.String(), end.String()); err != nil {
		return httpProblem(c, httpInternal(log, "cannot check segment overlap", err))
	} else if taken {
		return JSONProblemf(c, http.StatusConflict, "range %s - %s overlaps segment %d", begin, end, otherID)
	}

	log.Info("called", "net_id", netID, "seg_id", segID)
	if err := odb.UpdateNetworkSegment(ctx, segID, segType, begin.String(), end.String()); err != nil {
		return httpProblem(c, httpInternal(log, "cannot update segment", err))
	}
	a.logNetworkAction(ctx, c, log, "networks.segment.update",
		"updated segment %(segment)s of network %(network)s: %(type)s %(begin)s-%(end)s",
		map[string]any{"segment": segmentLabel(segment), "network": networkLabel(network),
			"type": segType, "begin": begin.String(), "end": end.String()})

	row, err := odb.GetNetworkSegmentRow(ctx, segID)
	if err != nil || row == nil {
		log.Error("cannot read the updated segment", "id", segID, logkey.Error, err)
		return JSONProblemf(c, http.StatusInternalServerError, "segment %d updated but cannot be read back", segID)
	}
	return c.JSON(http.StatusOK, map[string]any{"data": []any{row}, "info": fmt.Sprintf("segment %d updated", segID)})
}

// DeleteNetworkSegment handles DELETE /networks/{net_id}/segments/{seg_id}.
// As the historical collector, it takes the team responsible for the network.
func (a *Api) DeleteNetworkSegment(c echo.Context, netId string, segId string) error {
	log := echolog.GetLogHandler(c, "DeleteNetworkSegment")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if err := requireNetworkManager(c); err != nil {
		return err
	}
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	segID, err := parseRecordID("segment id", segId)
	if err != nil {
		return httpProblem(c, err)
	}
	network, err := a.networkForWrite(ctx, c, log, netID)
	if err != nil {
		return httpProblem(c, err)
	}
	segment, found, err := a.ODB.GetNetworkSegmentOf(ctx, netID, segID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read segment", err))
	}
	if !found {
		return JSONProblemf(c, http.StatusNotFound, "segment %d of network %d not found", segID, netID)
	}
	log.Info("called", "net_id", netID, "seg_id", segID)
	if err := a.ODB.DeleteNetworkSegment(ctx, segID); err != nil {
		return httpProblem(c, httpInternal(log, "cannot delete segment", err))
	}
	a.logNetworkAction(ctx, c, log, "networks.segment.delete", "deleted segment %(segment)s of network %(network)s",
		map[string]any{"segment": segmentLabel(segment), "network": networkLabel(network)})
	return c.JSON(http.StatusOK, map[string]any{"info": fmt.Sprintf("segment %s of network %s deleted", segmentLabel(segment), networkLabel(network))})
}

// GetNetworkSegmentResponsibles handles GET /networks/{net_id}/segments/{seg_id}/responsibles.
func (a *Api) GetNetworkSegmentResponsibles(c echo.Context, netId string, segId string, params server.GetNetworkSegmentResponsiblesParams) error {
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	segID, err := parseRecordID("segment id", segId)
	if err != nil {
		return httpProblem(c, err)
	}
	if _, found, err := a.ODB.GetNetworkSegmentOf(c.Request().Context(), netID, segID); err != nil {
		return httpProblem(c, httpInternal(echolog.GetLogHandler(c, "GetNetworkSegmentResponsibles"), "cannot read segment", err))
	} else if !found {
		return JSONProblemf(c, http.StatusNotFound, "segment %d of network %d not found", segID, netID)
	}
	return a.handleList(c, "GetNetworkSegmentResponsibles", "network_segment_responsible",
		listParams(params.Props, params.Limit, params.Offset, params.Meta, params.Stats, params.Orderby, params.Groupby, params.Filter),
		func(ctx context.Context, p cdb.ListParams) ([]map[string]any, error) {
			return a.ODB.GetNetworkSegmentResponsibles(ctx, segID, p)
		})
}

// segmentResponsibleRequest resolves the segment and the group of a
// responsible attachment or detachment the caller may make.
func (a *Api) segmentResponsibleRequest(ctx context.Context, c echo.Context, log *slog.Logger, netId, segId, groupId string) (cdb.NetworkRange, cdb.NetworkSegment, *cdb.AuthGroup, error) {
	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return cdb.NetworkRange{}, cdb.NetworkSegment{}, nil, err
	}
	segID, err := parseRecordID("segment id", segId)
	if err != nil {
		return cdb.NetworkRange{}, cdb.NetworkSegment{}, nil, err
	}
	network, segment, err := a.segmentForWrite(ctx, c, log, netID, segID)
	if err != nil {
		return network, segment, nil, err
	}
	group, found, err := a.ODB.AuthGroupByIDOrRole(ctx, groupId)
	if err != nil {
		return network, segment, nil, httpInternal(log, "cannot read group", err)
	}
	if !found {
		return network, segment, nil, httpErrorf(http.StatusNotFound, "group %s not found", groupId)
	}
	if group.Privilege {
		return network, segment, nil, httpErrorf(http.StatusBadRequest, "%s is a privilege, not an organisational group", group.Role)
	}
	return network, segment, group, nil
}

// PostNetworkSegmentResponsible handles POST
// /networks/{net_id}/segments/{seg_id}/responsibles/{group_id}.
func (a *Api) PostNetworkSegmentResponsible(c echo.Context, netId string, segId string, groupId string) error {
	log := echolog.GetLogHandler(c, "PostNetworkSegmentResponsible")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if !IsAuthByUser(c) {
		return denyRequest(c, http.StatusUnauthorized, "user authentication required")
	}
	network, segment, group, err := a.segmentResponsibleRequest(ctx, c, log, netId, segId, groupId)
	if err != nil {
		return httpProblem(c, err)
	}
	log.Info("called", "seg_id", segment.ID, "group_id", group.ID)
	added, err := a.ODB.AddNetworkSegmentResponsible(ctx, segment.ID, group.ID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot attach group", err))
	}
	if !added {
		return JSONProblemf(c, http.StatusConflict, "group %s is already responsible for segment %s", group.Role, segmentLabel(segment))
	}
	a.logNetworkAction(ctx, c, log, "networks.segment.attach", "attached group %(group)s to segment %(segment)s of network %(network)s",
		map[string]any{"group": group.Role, "segment": segmentLabel(segment), "network": networkLabel(network)})

	mapping := propsMapping["network_segment_responsible"]
	query, err := buildListQueryParameters(nil, nil, nil, nil, nil, nil, nil, mapping)
	if err == nil {
		var selectExprs []string
		if selectExprs, err = buildSelectClause(query.Props, mapping); err == nil {
			var rows []map[string]any
			rows, err = a.ODB.GetNetworkSegmentResponsible(ctx, segment.ID, group.ID, cdb.ListParams{
				IsManager: true, Props: query.Props, SelectExprs: selectExprs, TypeHints: buildTypeHints(query.Props, mapping),
			})
			if err == nil {
				return c.JSON(http.StatusOK, map[string]any{"data": rows,
					"info": fmt.Sprintf("attached group %s to segment %s", group.Role, segmentLabel(segment))})
			}
		}
	}
	log.Error("cannot read the attached group", logkey.Error, err)
	return JSONProblemf(c, http.StatusInternalServerError, "group attached but cannot be read back")
}

// DeleteNetworkSegmentResponsible handles DELETE
// /networks/{net_id}/segments/{seg_id}/responsibles/{group_id}.
func (a *Api) DeleteNetworkSegmentResponsible(c echo.Context, netId string, segId string, groupId string) error {
	log := echolog.GetLogHandler(c, "DeleteNetworkSegmentResponsible")
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	if !IsAuthByUser(c) {
		return denyRequest(c, http.StatusUnauthorized, "user authentication required")
	}
	network, segment, group, err := a.segmentResponsibleRequest(ctx, c, log, netId, segId, groupId)
	if err != nil {
		return httpProblem(c, err)
	}
	log.Info("called", "seg_id", segment.ID, "group_id", group.ID)
	removed, err := a.ODB.RemoveNetworkSegmentResponsible(ctx, segment.ID, group.ID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot detach group", err))
	}
	if !removed {
		return JSONProblemf(c, http.StatusNotFound, "group %s is not responsible for segment %s", group.Role, segmentLabel(segment))
	}
	a.logNetworkAction(ctx, c, log, "networks.segment.detach", "detached group %(group)s from segment %(segment)s of network %(network)s",
		map[string]any{"group": group.Role, "segment": segmentLabel(segment), "network": networkLabel(network)})
	return c.JSON(http.StatusOK, map[string]any{"info": fmt.Sprintf("detached group %s from segment %s", group.Role, segmentLabel(segment))})
}

// networkIPRange is a range of addresses GET /networks/{net_id}/ips lists.
type networkIPRange struct {
	segID      *int
	segType    string
	begin, end uint32
}

// GetNetworkIps handles GET /networks/{net_id}/ips, as the historical
// collector's rest_get_network_ips, without the DNS records.
func (a *Api) GetNetworkIps(c echo.Context, netId string, params server.GetNetworkIpsParams) error {
	log := echolog.GetLogHandler(c, "GetNetworkIps")
	odb := a.ODB
	ctx, cancel := context.WithTimeout(c.Request().Context(), a.SyncTimeout)
	defer cancel()

	netID, err := parseRecordID("network id", netId)
	if err != nil {
		return httpProblem(c, err)
	}
	network, found, err := odb.GetNetworkRange(ctx, netID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read network", err))
	}
	if !found {
		return JSONProblemf(c, http.StatusNotFound, "network %d not found", netID)
	}

	var ranges []networkIPRange
	count, err := odb.CountNetworkSegments(ctx, netID)
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot count segments", err))
	}
	if count == 0 {
		begin, errB := netip.ParseAddr(network.Begin)
		end, errE := netip.ParseAddr(network.End)
		if errB != nil || errE != nil || !begin.Is4() || !end.Is4() {
			return JSONProblemf(c, http.StatusConflict, "network %d has no usable range", netID)
		}
		ranges = append(ranges, networkIPRange{begin: addrU32(begin), end: addrU32(end)})
	} else {
		var groupIDs []int64
		if !IsManager(c) {
			if userID := authUserID(c); userID != nil {
				if groupIDs, err = odb.UserGroupIDs(ctx, *userID); err != nil {
					return httpProblem(c, httpInternal(log, "cannot get the groups of the user", err))
				}
			}
		}
		segments, err := odb.GetNetworkSegmentsOf(ctx, netID, IsManager(c), groupIDs)
		if err != nil {
			return httpProblem(c, httpInternal(log, "cannot read segments", err))
		}
		if len(segments) == 0 {
			return JSONProblemf(c, http.StatusForbidden, "responsible for no segment of network %d", netID)
		}
		for _, s := range segments {
			begin, errB := netip.ParseAddr(s.Begin)
			end, errE := netip.ParseAddr(s.End)
			if errB != nil || errE != nil || !begin.Is4() || !end.Is4() || end.Less(begin) {
				continue
			}
			id := s.ID
			ranges = append(ranges, networkIPRange{segID: &id, segType: s.Type, begin: addrU32(begin), end: addrU32(end)})
		}
	}
	total := big.NewInt(0)
	for _, r := range ranges {
		total.Add(total, big.NewInt(int64(r.end)-int64(r.begin)+1))
	}
	if total.Cmp(big.NewInt(maxNetworkIps)) > 0 {
		return JSONProblemf(c, http.StatusBadRequest, "%s addresses to list, more than %d", total, maxNetworkIps)
	}
	if len(ranges) == 0 {
		return c.JSON(http.StatusOK, map[string]any{"data": []any{}, "meta": map[string]any{"count": 0}})
	}

	first, last := ranges[0].begin, ranges[0].end
	for _, r := range ranges {
		first, last = min(first, r.begin), max(last, r.end)
	}
	addresses, err := odb.NodeAddressesBetween(ctx, u32Addr(first).String(), u32Addr(last).String())
	if err != nil {
		return httpProblem(c, httpInternal(log, "cannot read node addresses", err))
	}
	nodesByAddr := make(map[string][]server.NetworkIpNode)
	for _, na := range addresses {
		addr, err := netip.ParseAddr(na.Addr)
		if err != nil {
			continue
		}
		key := addr.String()
		nodesByAddr[key] = append(nodesByAddr[key], server.NetworkIpNode{NodeId: na.NodeID, Nodename: na.Nodename})
	}

	free := params.Free != nil && *params.Free
	offset := 0
	if params.Offset != nil && *params.Offset > 0 {
		offset = *params.Offset
	}
	limit := 0
	if params.Limit != nil && *params.Limit > 0 {
		limit = *params.Limit
	}
	data := []server.NetworkIpRow{}
	matched := 0
	for _, r := range ranges {
		for n := uint64(r.begin); n <= uint64(r.end); n++ {
			ip := u32Addr(uint32(n)).String()
			nodes := nodesByAddr[ip]
			if free && len(nodes) > 0 {
				continue
			}
			matched++
			if matched <= offset || (limit > 0 && len(data) >= limit) {
				continue
			}
			if nodes == nil {
				nodes = []server.NetworkIpNode{}
			}
			data = append(data, server.NetworkIpRow{Ip: ip, SegId: r.segID, SegType: &r.segType, Nodes: nodes})
		}
	}
	log.Info("called", "net_id", netID, "count", matched)
	return c.JSON(http.StatusOK, map[string]any{"data": data, "meta": map[string]any{"count": matched, "offset": offset, "limit": limit}})
}
