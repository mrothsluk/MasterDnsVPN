package client

import (
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func (r *ResolverRuntime) SelectTargetsForPacket(c *Client, packetType uint8, streamID uint16) ([]Connection, error) {
	targetCount := 1
	if c != nil {
		targetCount = c.runtimePacketDuplicationCount(packetType)
	}
	return r.SelectTargetsForPacketCount(c, packetType, streamID, targetCount)
}

func (r *ResolverRuntime) SelectTargetsForPacketCount(c *Client, packetType uint8, streamID uint16, targetCount int) ([]Connection, error) {
	if targetCount < 1 {
		targetCount = 1
	}

	if c == nil || r == nil || r.balancer == nil || streamID == 0 || r.balancer.ValidCount() <= 0 {
		return r.selectUniqueConnections(c, targetCount)
	}

	if packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND {
		return r.selectUniqueConnections(c, targetCount)
	}

	stream, ok := c.getStream(streamID)
	if !ok || stream == nil {
		return r.selectUniqueConnections(c, targetCount)
	}

	var (
		preferred Connection
		found     bool
	)

	if packetType == Enums.PACKET_STREAM_RESEND {
		preferred, found = r.selectStreamPreferredConnectionForResend(c, stream.StreamID)
	} else {
		preferred, found = r.ensureStreamPreferredConnection(c, stream.StreamID)
	}

	if !found {
		return r.selectUniqueConnections(c, targetCount)
	}

	if targetCount <= 1 {
		return []Connection{preferred}, nil
	}

	if cached, ok := r.getCachedStreamConnectionPlan(stream.StreamID, preferred.Key, targetCount); ok {
		return cached, nil
	}

	selected := make([]Connection, 0, targetCount)
	selected = append(selected, preferred)

	for _, connection := range r.balancer.GetUniqueConnections(targetCount) {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		dup := false
		for _, existing := range selected {
			if existing.Key == connection.Key {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		if c != nil && c.isRuntimeDisabledResolver(connection.Key) {
			continue
		}
		selected = append(selected, connection)
		if len(selected) >= targetCount {
			r.cacheStreamConnectionPlan(stream.StreamID, preferred.Key, targetCount, selected)
			return selected, nil
		}
	}

	if len(selected) == 0 {
		return nil, ErrNoValidConnections
	}

	r.cacheStreamConnectionPlan(stream.StreamID, preferred.Key, targetCount, selected)
	return selected, nil
}

func (r *ResolverRuntime) selectStreamPreferredConnectionForResend(c *Client, streamID uint16) (Connection, bool) {
	if r == nil || c == nil || streamID == 0 {
		return Connection{}, false
	}
	state := r.routeState(streamID)
	r.streamMu.Lock()
	state.ResolverResendStreak++
	streak := state.ResolverResendStreak
	r.streamMu.Unlock()

	if streak >= r.failoverThreshold {
		return r.maybeFailoverStreamPreferredConnection(c, streamID)
	}
	return r.ensureStreamPreferredConnection(c, streamID)
}

func (r *ResolverRuntime) getValidStreamPreferredConnection(c *Client, streamID uint16) (Connection, bool) {
	if r == nil || c == nil || streamID == 0 {
		return Connection{}, false
	}
	state := r.routeState(streamID)
	r.streamMu.RLock()
	preferredKey := state.PreferredResolverKey
	r.streamMu.RUnlock()
	if preferredKey == "" || c.isRuntimeDisabledResolver(preferredKey) {
		return Connection{}, false
	}
	connection, ok := c.GetConnectionByKey(preferredKey)
	if !ok || !connection.IsValid {
		return Connection{}, false
	}
	return connection, true
}

func (r *ResolverRuntime) assignStreamPreferredConnection(streamID uint16, connection Connection, markFailover bool) (Connection, bool) {
	if r == nil || streamID == 0 {
		return Connection{}, false
	}
	state := r.routeState(streamID)
	r.streamMu.Lock()
	defer r.streamMu.Unlock()
	if !connection.IsValid || connection.Key == "" {
		state.PreferredResolverKey = ""
		return Connection{}, false
	}
	state.PreferredResolverKey = connection.Key
	state.ResolverResendStreak = 0
	state.CachedPlan = nil
	state.CachedPlanFor = ""
	state.CachedPlanSize = 0
	state.CachedPlanVersion = 0
	if markFailover {
		state.LastFailoverAt = time.Now()
	}
	return connection, true
}

func (r *ResolverRuntime) ensureStreamPreferredConnection(c *Client, streamID uint16) (Connection, bool) {
	if preferred, ok := r.getValidStreamPreferredConnection(c, streamID); ok {
		return preferred, true
	}
	state := r.routeState(streamID)
	r.streamMu.RLock()
	excludeKey := state.PreferredResolverKey
	r.streamMu.RUnlock()
	if fallback, ok := r.selectAlternateConnection(c, excludeKey); ok {
		return r.assignStreamPreferredConnection(streamID, fallback, false)
	}
	return Connection{}, false
}

func (r *ResolverRuntime) maybeFailoverStreamPreferredConnection(c *Client, streamID uint16) (Connection, bool) {
	current, ok := r.getValidStreamPreferredConnection(c, streamID)
	if !ok {
		return r.ensureStreamPreferredConnection(c, streamID)
	}
	state := r.routeState(streamID)
	r.streamMu.RLock()
	lastSwitch := state.LastFailoverAt
	r.streamMu.RUnlock()
	if !lastSwitch.IsZero() && time.Since(lastSwitch) < r.failoverCooldown {
		return current, true
	}
	replacement, ok := r.selectAlternateConnection(c, current.Key)
	if !ok {
		return current, true
	}
	return r.assignStreamPreferredConnection(streamID, replacement, true)
}

func (r *ResolverRuntime) noteStreamProgress(streamID uint16) {
	if r == nil || streamID == 0 {
		return
	}
	state := r.routeState(streamID)
	r.streamMu.Lock()
	state.ResolverResendStreak = 0
	r.streamMu.Unlock()
}

func (r *ResolverRuntime) getCachedStreamConnectionPlan(streamID uint16, preferredKey string, targetCount int) ([]Connection, bool) {
	if r == nil || r.balancer == nil || streamID == 0 || preferredKey == "" || targetCount <= 1 {
		return nil, false
	}
	version := r.balancer.SnapshotVersion()
	state := r.routeState(streamID)
	r.streamMu.RLock()
	defer r.streamMu.RUnlock()
	if state.CachedPlanVersion != version ||
		state.CachedPlanFor != preferredKey ||
		state.CachedPlanSize != targetCount ||
		len(state.CachedPlan) == 0 {
		return nil, false
	}
	return state.CachedPlan, true
}

func (r *ResolverRuntime) cacheStreamConnectionPlan(streamID uint16, preferredKey string, targetCount int, selected []Connection) {
	if r == nil || r.balancer == nil || streamID == 0 || preferredKey == "" || targetCount <= 1 || len(selected) == 0 {
		return
	}
	cached := make([]Connection, len(selected))
	copy(cached, selected)
	version := r.balancer.SnapshotVersion()
	state := r.routeState(streamID)
	r.streamMu.Lock()
	state.CachedPlan = cached
	state.CachedPlanFor = preferredKey
	state.CachedPlanSize = targetCount
	state.CachedPlanVersion = version
	r.streamMu.Unlock()
}

func (r *ResolverRuntime) clearPreferredResolverReferences(serverKey string) {
	if r == nil || serverKey == "" {
		return
	}
	r.streamMu.Lock()
	defer r.streamMu.Unlock()
	for _, state := range r.streamRoutes {
		if state == nil || state.PreferredResolverKey != serverKey {
			continue
		}
		state.PreferredResolverKey = ""
		state.ResolverResendStreak = 0
		state.CachedPlan = nil
		state.CachedPlanFor = ""
		state.CachedPlanSize = 0
		state.CachedPlanVersion = 0
	}
}

func (r *ResolverRuntime) selectUniqueConnections(c *Client, requiredCount int) ([]Connection, error) {
	if r == nil || r.balancer == nil {
		return nil, ErrNoValidConnections
	}

	connections := r.balancer.GetUniqueConnections(requiredCount)
	if len(connections) == 0 {
		return nil, ErrNoValidConnections
	}

	filtered := connections[:0]
	for _, conn := range connections {
		if c != nil && c.isRuntimeDisabledResolver(conn.Key) {
			continue
		}
		filtered = append(filtered, conn)
	}
	if len(filtered) == 0 {
		return nil, ErrNoValidConnections
	}

	return filtered, nil
}

func (r *ResolverRuntime) selectAlternateConnection(c *Client, excludeKey string) (Connection, bool) {
	if r == nil || r.balancer == nil {
		return Connection{}, false
	}

	if excludeKey != "" {
		if replacement, ok := r.balancer.GetBestConnectionExcluding(excludeKey); ok && (c == nil || !c.isRuntimeDisabledResolver(replacement.Key)) {
			return replacement, true
		}
	}

	for _, connection := range r.balancer.GetAllValidConnections() {
		if !connection.IsValid || connection.Key == "" {
			continue
		}
		if c != nil && c.isRuntimeDisabledResolver(connection.Key) {
			continue
		}
		if excludeKey != "" && connection.Key == excludeKey {
			continue
		}
		return connection, true
	}

	return Connection{}, false
}
