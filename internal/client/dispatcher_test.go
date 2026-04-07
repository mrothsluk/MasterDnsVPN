package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/mlq"
)

func TestAsyncStreamDispatcherDrainsQueuedWorkAfterSingleWake(t *testing.T) {
	c := createTestClient(t)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatalf("BuildConnectionMap returned error: %v", err)
	}

	c.encodeQueue = make(chan encodeTask, 4)
	c.active_streams = make(map[uint16]*Stream_client)

	stream := &Stream_client{
		client:   c,
		StreamID: 1,
		txQueue:  mlq.New[*clientStreamTXPacket](8),
	}
	c.active_streams[stream.StreamID] = stream
	c.bumpStreamSetVersion()

	if !stream.PushTXPacket(0, 0x99, 1, 0, 0, 0, 0, []byte("first")) {
		t.Fatal("expected first packet to enqueue")
	}
	if !stream.PushTXPacket(0, 0x98, 2, 0, 0, 0, 0, []byte("second")) {
		t.Fatal("expected second packet to enqueue")
	}

	c.clearDispatchSignal()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	c.asyncWG.Add(1)
	go func() {
		defer close(done)
		c.asyncStreamDispatcher(ctx)
	}()

	select {
	case c.dispatchSignal <- struct{}{}:
	default:
	}

	waitForCondition(t, time.Second, func() bool {
		return len(c.encodeQueue) == 2
	}, "expected dispatcher to drain both queued packets after a single wake signal")

	cancel()
	c.asyncWG.Wait()
}

func TestAsyncStreamDispatcherWakesOnEncodeQueueSpaceSignal(t *testing.T) {
	c := createTestClient(t)
	c.cfg.DispatcherIdlePollIntervalSeconds = 0.01
	c.dispatchSignal = make(chan struct{}, 1)
	c.encodeQueueSpaceSignal = make(chan struct{}, 1)
	c.active_streams = make(map[uint16]*Stream_client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.asyncWG.Add(1)
	go c.asyncStreamDispatcher(ctx)

	c.encodeQueueSpaceSignal <- struct{}{}
	time.Sleep(40 * time.Millisecond)

	if len(c.encodeQueueSpaceSignal) != 0 {
		t.Fatal("expected dispatcher to consume encodeQueueSpaceSignal wakeup")
	}

	cancel()
	c.asyncWG.Wait()
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal(msg)
}
