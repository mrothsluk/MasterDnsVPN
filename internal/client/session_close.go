// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	sessionCloseFanoutLimit   = 10
	sessionCloseDefaultWindow = time.Second
)

func (c *Client) BestEffortSessionClose(timeout time.Duration) {
	if c == nil || !c.sessionReady || c.sessionID == 0 {
		return
	}

	targets := c.activeSessionCloseTargets(sessionCloseFanoutLimit)
	if len(targets) == 0 {
		return
	}

	// Hard limit of 1 second for session close as per user requirement
	if timeout > time.Second || timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	queries := make(map[string][]byte, len(targets))

	var wg sync.WaitGroup
	done := make(chan struct{})

	for _, conn := range targets {
		query, ok := queries[conn.Domain]
		if !ok {
			built, err := c.buildSessionCloseQuery(conn.Domain)
			if err != nil {
				continue
			}
			query = built
			queries[conn.Domain] = query
		}

		connCopy := conn
		packetCopy := query
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.sendOneWaySessionPacket(connCopy, packetCopy, deadline)
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
	}
}

func (c *Client) activeSessionCloseTargets(limit int) []Connection {
	if c == nil || limit <= 0 {
		return nil
	}

	limit = min(limit, sessionCloseFanoutLimit)
	seen := make(map[string]struct{}, limit)
	targets := make([]Connection, 0, limit)
	candidateCount := min(len(c.connections), max(limit, limit*max(1, len(c.cfg.Domains))))

	conns := c.balancer.GetUniqueConnections(candidateCount)
	for _, conn := range conns {
		if !conn.IsValid || conn.ResolverLabel == "" {
			continue
		}
		if _, ok := seen[conn.ResolverLabel]; ok {
			continue
		}
		seen[conn.ResolverLabel] = struct{}{}
		targets = append(targets, conn)
		if len(targets) >= limit {
			return targets
		}
	}

	for _, conn := range c.connections {
		if !conn.IsValid || conn.ResolverLabel == "" {
			continue
		}
		if _, ok := seen[conn.ResolverLabel]; ok {
			continue
		}
		seen[conn.ResolverLabel] = struct{}{}
		targets = append(targets, conn)
		if len(targets) >= limit {
			break
		}
	}

	return targets
}

func (c *Client) buildSessionCloseQuery(domain string) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:     c.sessionID,
		PacketType:    Enums.PACKET_SESSION_CLOSE,
		SessionCookie: c.sessionCookie,
	})
}

func (c *Client) sendOneWaySessionPacket(connection Connection, packet []byte, deadline time.Time) {
	if c != nil && c.sendOneWayPacketFn != nil {
		_ = c.sendOneWayPacketFn(connection, packet, deadline)
		return
	}
	c.sendFastOneWayUDP(connection.ResolverLabel, packet, deadline)
}
