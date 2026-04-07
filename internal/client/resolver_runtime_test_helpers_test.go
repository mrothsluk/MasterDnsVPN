package client

import "time"

func testSetResolverHealthState(c *Client, key string, state *resolverHealthState) {
	c.runtime.healthMu.Lock()
	c.runtime.health[key] = state
	c.runtime.healthMu.Unlock()
}

func testSetResolverRecheck(c *Client, key string, meta resolverRecheckState) {
	c.runtime.healthMu.Lock()
	c.runtime.recheck[key] = meta
	c.runtime.healthMu.Unlock()
}

func testSetRuntimeDisabled(c *Client, key string, state resolverDisabledState) {
	c.runtime.healthMu.Lock()
	c.runtime.runtimeDisabled[key] = state
	c.runtime.healthMu.Unlock()
}

func testGetRuntimeDisabled(c *Client, key string) (resolverDisabledState, bool) {
	c.runtime.healthMu.RLock()
	defer c.runtime.healthMu.RUnlock()
	state, ok := c.runtime.runtimeDisabled[key]
	return state, ok
}

func testGetResolverRecheck(c *Client, key string) resolverRecheckState {
	c.runtime.healthMu.RLock()
	defer c.runtime.healthMu.RUnlock()
	return c.runtime.recheck[key]
}

func testGetResolverHealthState(c *Client, key string) *resolverHealthState {
	c.runtime.healthMu.RLock()
	defer c.runtime.healthMu.RUnlock()
	return c.runtime.health[key]
}

func testSetRoutePreferred(c *Client, streamID uint16, key string) {
	state := c.runtime.routeState(streamID)
	c.runtime.streamMu.Lock()
	state.PreferredResolverKey = key
	c.runtime.streamMu.Unlock()
}

func testSetRouteResendStreak(c *Client, streamID uint16, streak int) {
	state := c.runtime.routeState(streamID)
	c.runtime.streamMu.Lock()
	state.ResolverResendStreak = streak
	c.runtime.streamMu.Unlock()
}

func testSetRouteLastFailoverAt(c *Client, streamID uint16, at time.Time) {
	state := c.runtime.routeState(streamID)
	c.runtime.streamMu.Lock()
	state.LastFailoverAt = at
	c.runtime.streamMu.Unlock()
}

func testGetRouteState(c *Client, streamID uint16) streamRouteState {
	state := c.runtime.routeState(streamID)
	c.runtime.streamMu.RLock()
	defer c.runtime.streamMu.RUnlock()
	return *state
}
