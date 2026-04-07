// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

func buildTestClientWithResolvers(cfg config.ClientConfig, keys ...string) *Client {
	c := New(cfg, nil, nil)
	c.connections = make([]Connection, 0, len(keys))
	c.connectionsByKey = make(map[string]int, len(keys))
	c.active_streams = make(map[uint16]*Stream_client)

	for i, key := range keys {
		conn := Connection{
			Key:           key,
			Domain:        key + ".example.com",
			Resolver:      "127.0.0.1",
			ResolverPort:  5300 + i,
			ResolverLabel: "127.0.0.1:" + string(rune('0'+i)),
			IsValid:       true,
		}
		c.connections = append(c.connections, conn)
		c.connectionsByKey[key] = i
	}

	ptrs := make([]*Connection, len(c.connections))
	for i := range c.connections {
		ptrs[i] = &c.connections[i]
	}
	c.balancer.SetConnections(ptrs)
	if c.runtime != nil {
		c.runtime.LoadConnections(c.connections)
	}
	return c
}

func testStream(id uint16) *Stream_client {
	return &Stream_client{
		StreamID: id,
		Status:   streamStatusActive,
	}
}

func TestSelectTargetConnectionsForPacketPrefersStickyStreamResolver(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount: 2,
	}, "a", "b", "c")

	stream := testStream(7)
	c.active_streams[stream.StreamID] = stream
	testSetRoutePreferred(c, stream.StreamID, "b")
	testSetRouteLastFailoverAt(c, stream.StreamID, time.Now())

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("unexpected selected count: got=%d want=2", len(selected))
	}
	if selected[0].Key != "b" {
		t.Fatalf("expected preferred resolver first, got=%q", selected[0].Key)
	}
}

func TestEnsureStreamPreferredConnectionSkipsRuntimeDisabledResolver(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount: 1,
	}, "a", "b")

	stream := testStream(8)
	c.active_streams[stream.StreamID] = stream
	testSetRoutePreferred(c, stream.StreamID, "a")

	testSetRuntimeDisabled(c, "a", resolverDisabledState{
		DisabledAt:  time.Now(),
		NextRetryAt: time.Now().Add(time.Minute),
		Cause:       "test",
	})

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("unexpected selected count: got=%d want=1", len(selected))
	}
	if selected[0].Key != "b" {
		t.Fatalf("expected runtime-disabled preferred resolver to be skipped, got=%q", selected[0].Key)
	}
	if state := testGetRouteState(c, stream.StreamID); state.PreferredResolverKey != "b" {
		t.Fatalf("expected preferred resolver to switch immediately, got=%q", state.PreferredResolverKey)
	}
}

func TestSelectTargetConnectionsForPacketFailsOverOnResendStreak(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:                1,
		StreamResolverFailoverResendThreshold: 1,
		StreamResolverFailoverCooldownSec:     0.1,
	}, "a", "b")

	stream := testStream(9)
	c.active_streams[stream.StreamID] = stream
	testSetRoutePreferred(c, stream.StreamID, "a")
	testSetRouteLastFailoverAt(c, stream.StreamID, time.Now().Add(-2*time.Second))

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_RESEND, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("unexpected selected count: got=%d want=1", len(selected))
	}
	if selected[0].Key != "b" {
		t.Fatalf("expected resend failover to switch preferred resolver, got=%q", selected[0].Key)
	}
}

func TestEnsureStreamPreferredConnectionDoesNotStartFailoverCooldown(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:                1,
		StreamResolverFailoverResendThreshold: 1,
		StreamResolverFailoverCooldownSec:     5.0,
	}, "a", "b")

	stream := testStream(12)
	c.active_streams[stream.StreamID] = stream

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("unexpected selected count: got=%d want=1", len(selected))
	}
	if selected[0].Key != "a" {
		t.Fatalf("expected initial preferred resolver to be a, got=%q", selected[0].Key)
	}
	if state := testGetRouteState(c, stream.StreamID); !state.LastFailoverAt.IsZero() {
		t.Fatal("expected initial preferred assignment to not stamp LastResolverFailoverAt")
	}

	selected, err = c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_RESEND, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("unexpected selected count after resend: got=%d want=1", len(selected))
	}
	if selected[0].Key != "b" {
		t.Fatalf("expected immediate failover from initial preferred resolver, got=%q", selected[0].Key)
	}
	if state := testGetRouteState(c, stream.StreamID); state.LastFailoverAt.IsZero() {
		t.Fatal("expected real failover to stamp LastResolverFailoverAt")
	}
}

func TestSelectTargetConnectionsForPacketRespectsFailoverCooldown(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:                1,
		StreamResolverFailoverResendThreshold: 1,
		StreamResolverFailoverCooldownSec:     5.0,
	}, "a", "b")

	stream := testStream(10)
	c.active_streams[stream.StreamID] = stream
	testSetRoutePreferred(c, stream.StreamID, "a")
	testSetRouteLastFailoverAt(c, stream.StreamID, time.Now())

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_RESEND, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("unexpected selected count: got=%d want=1", len(selected))
	}
	if selected[0].Key != "a" {
		t.Fatalf("expected cooldown to keep current preferred resolver, got=%q", selected[0].Key)
	}
}

func TestSelectTargetConnectionsForPacketUsesSetupDuplicationCount(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:      1,
		SetupPacketDuplicationCount: 3,
	}, "a", "b", "c")

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_SYN, 99)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket returned error: %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("unexpected selected count: got=%d want=3", len(selected))
	}
}

func TestSelectTargetConnectionsForPacketAppliesDuplicationCountToPing(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 4,
	}, "a", "b", "c", "d")

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_PING, 42)
	if err != nil {
		t.Fatalf("packet %s: unexpected error: %v", Enums.PacketTypeName(Enums.PACKET_PING), err)
	}
	if len(selected) != 2 {
		t.Fatalf("packet %s: expected duplication count to be capped at 2, got=%d", Enums.PacketTypeName(Enums.PACKET_PING), len(selected))
	}
}

func TestSelectTargetConnectionsForPacketCountUsesPlannerCount(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount:      5,
		SetupPacketDuplicationCount: 5,
	}, "a", "b", "c", "d")

	selected, err := c.runtime.SelectTargetsForPacketCount(c, Enums.PACKET_PING, 42, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("expected planner-selected count to be honored, got=%d", len(selected))
	}
}

func TestNoteStreamProgressResetsResolverResendStreak(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")

	stream := testStream(11)
	c.active_streams[stream.StreamID] = stream
	testSetRouteResendStreak(c, stream.StreamID, 4)

	c.runtime.noteStreamProgress(stream.StreamID)

	if state := testGetRouteState(c, stream.StreamID); state.ResolverResendStreak != 0 {
		t.Fatalf("expected resend streak reset, got=%d", state.ResolverResendStreak)
	}
}

func TestSelectAlternateStreamConnectionUsesBestScoredCandidate(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy: BalancingLowestLatency,
	}, "a", "b", "c")

	for i := 0; i < 6; i++ {
		c.balancer.ReportSend("a")
		c.balancer.ReportSuccess("a", 2*time.Millisecond)
		c.balancer.ReportSend("b")
		c.balancer.ReportSuccess("b", 6*time.Millisecond)
		c.balancer.ReportSend("c")
		c.balancer.ReportSuccess("c", 10*time.Millisecond)
	}

	selected, ok := c.runtime.selectAlternateConnection(c, "a")
	if !ok {
		t.Fatal("expected alternate connection")
	}
	if selected.Key != "b" {
		t.Fatalf("expected best candidate after excluding a to be b, got=%q", selected.Key)
	}
}
