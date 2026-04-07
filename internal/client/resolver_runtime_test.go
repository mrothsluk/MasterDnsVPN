package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

func TestBuildConnectionMapLoadsResolverRuntimeCatalog(t *testing.T) {
	c := createTestClient(t)

	if err := c.BuildConnectionMap(); err != nil {
		t.Fatalf("BuildConnectionMap returned error: %v", err)
	}

	if c.runtime == nil {
		t.Fatal("expected resolver runtime to be initialized")
	}

	if len(c.runtime.Connections()) != len(c.connections) {
		t.Fatalf("expected runtime catalog size %d, got %d", len(c.connections), len(c.runtime.Connections()))
	}

	for _, conn := range c.connections {
		got, ok := c.runtime.GetConnectionByKey(conn.Key)
		if !ok {
			t.Fatalf("expected resolver runtime to contain %q", conn.Key)
		}
		if got.Key != conn.Key || got.Domain != conn.Domain || got.ResolverLabel != conn.ResolverLabel {
			t.Fatalf("unexpected runtime connection copy for %q: %+v", conn.Key, got)
		}
	}
}

func TestResolverRuntimeRefreshAndMTUSync(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")
	c.runtime = NewResolverRuntime(c.balancer, c.cfg.RecheckBatchSize, c.streamResolverFailoverResendThreshold, c.streamResolverFailoverCooldown)
	c.runtime.LoadConnections(c.connections)

	c.connections[0].UploadMTUBytes = 91
	c.connections[0].UploadMTUChars = 145
	c.connections[0].DownloadMTUBytes = 181
	c.connections[0].IsValid = false

	c.runtime.RefreshFromConnections(c.connections)

	got, ok := c.runtime.GetConnectionByKey("a")
	if !ok {
		t.Fatal("expected runtime connection")
	}
	if got.UploadMTUBytes != 91 || got.UploadMTUChars != 145 || got.DownloadMTUBytes != 181 {
		t.Fatalf("expected MTU sync into runtime, got up=%d chars=%d down=%d", got.UploadMTUBytes, got.UploadMTUChars, got.DownloadMTUBytes)
	}
	if got.IsValid {
		t.Fatal("expected validity refresh into runtime")
	}
}

func TestResolverRuntimeSelectTargetsUsesCentralSelectionAPI(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		PacketDuplicationCount: 2,
	}, "a", "b", "c")

	stream := testStream(77)
	c.active_streams[stream.StreamID] = stream
	testSetRoutePreferred(c, stream.StreamID, "b")
	testSetRouteLastFailoverAt(c, stream.StreamID, time.Now())

	selected, err := c.runtime.SelectTargetsForPacket(c, Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("SelectTargetsForPacket returned error: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("unexpected selected count: got=%d want=2", len(selected))
	}
	if selected[0].Key != "b" {
		t.Fatalf("expected preferred resolver first, got=%q", selected[0].Key)
	}
}
