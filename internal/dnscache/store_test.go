// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnscache

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLookupOrCreatePendingAndReadyFlow(t *testing.T) {
	store := New(8, time.Minute, 30*time.Second)
	now := time.Now()
	key := BuildKey("example.com", 1, 1)

	first := store.LookupOrCreatePending(key, "example.com", 1, 1, now)
	if !first.DispatchNeeded || first.Status != StatusPending {
		t.Fatalf("unexpected first result: %+v", first)
	}

	second := store.LookupOrCreatePending(key, "example.com", 1, 1, now.Add(5*time.Second))
	if second.DispatchNeeded {
		t.Fatalf("pending entry should not dispatch again before timeout: %+v", second)
	}

	response := []byte{0x12, 0x34, 0x81, 0x80}
	store.SetReady(key, "example.com", 1, 1, response, now.Add(6*time.Second))
	got, ok := store.GetReady(key, []byte{0xAA, 0xBB, 0x01, 0x00}, now.Add(7*time.Second))
	if !ok {
		t.Fatal("expected ready cache hit")
	}
	if binary.BigEndian.Uint16(got[:2]) != 0xAABB {
		t.Fatalf("response id was not patched: got=%#x", binary.BigEndian.Uint16(got[:2]))
	}
}

func TestPendingEntryBecomesDispatchableAgainAfterTimeout(t *testing.T) {
	store := New(8, time.Minute, 30*time.Second)
	now := time.Now()
	key := BuildKey("example.com", 1, 1)

	_ = store.LookupOrCreatePending(key, "example.com", 1, 1, now)
	result := store.LookupOrCreatePending(key, "example.com", 1, 1, now.Add(31*time.Second))
	if !result.DispatchNeeded {
		t.Fatalf("pending entry should dispatch again after timeout: %+v", result)
	}
}

func TestStoreEvictsLeastRecentlyUsedEntries(t *testing.T) {
	store := New(1, time.Minute, 30*time.Second)
	now := time.Now()
	firstKey := BuildKey("a.com", 1, 1)
	secondKey := BuildKey("b.com", 1, 1)

	store.SetReady(firstKey, "a.com", 1, 1, []byte{0, 1, 2, 3}, now)
	store.SetReady(secondKey, "b.com", 1, 1, []byte{0, 2, 3, 4}, now.Add(time.Second))

	if _, ok := store.Snapshot(firstKey); ok {
		t.Fatal("least recently used entry should have been evicted")
	}
	if _, ok := store.Snapshot(secondKey); !ok {
		t.Fatal("most recent entry should remain in cache")
	}
}

func TestPatchResponseForQueryCopiesFlagsAndID(t *testing.T) {
	rawResponse := []byte{0x00, 0x00, 0x81, 0x80}
	rawQuery := []byte{0x12, 0x34, 0x01, 0x20}
	patched := PatchResponseForQuery(rawResponse, rawQuery)
	if !bytes.Equal(patched[:2], rawQuery[:2]) {
		t.Fatal("query id was not copied")
	}
	if binary.BigEndian.Uint16(patched[2:4])&0x0110 != binary.BigEndian.Uint16(rawQuery[2:4])&0x0110 {
		t.Fatal("RD/CD bits were not copied from query")
	}
}

func TestSaveAndLoadFromFileSkipsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	now := time.Unix(1700000000, 0)

	store := New(8, time.Minute, 30*time.Second)
	freshKey := BuildKey("fresh.example", 1, 1)
	expiredKey := BuildKey("expired.example", 1, 1)
	store.SetReady(freshKey, "fresh.example", 1, 1, []byte{0x00, 0x00, 0x81, 0x80}, now)
	store.SetReady(expiredKey, "expired.example", 1, 1, []byte{0x00, 0x00, 0x81, 0x80}, now.Add(-2*time.Minute))

	if _, err := store.SaveToFile(path, now); err != nil {
		t.Fatalf("SaveToFile returned error: %v", err)
	}

	loaded := New(8, time.Minute, 30*time.Second)
	count, err := loaded.LoadFromFile(path, now)
	if err != nil {
		t.Fatalf("LoadFromFile returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("unexpected loaded count: got=%d want=1", count)
	}
	if _, ok := loaded.Snapshot(freshKey); !ok {
		t.Fatal("expected fresh entry to be loaded")
	}
	if _, ok := loaded.Snapshot(expiredKey); ok {
		t.Fatal("expired entry should not be loaded")
	}
}

func TestSaveToFileSkipsPendingEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	now := time.Unix(1700000000, 0)

	store := New(8, time.Minute, 30*time.Second)
	key := BuildKey("pending.example", 1, 1)
	_ = store.LookupOrCreatePending(key, "pending.example", 1, 1, now)

	count, err := store.SaveToFile(path, now)
	if err != nil {
		t.Fatalf("SaveToFile returned error: %v", err)
	}
	if count != 0 {
		t.Fatalf("pending entry should not be saved: got=%d", count)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected cache file to be written: %v", err)
	}
}
