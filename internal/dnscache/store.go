// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnscache

import (
	"container/list"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Status uint8

const (
	StatusPending Status = iota + 1
	StatusReady
)

type Entry struct {
	Domain         string
	QuestionType   uint16
	QuestionClass  uint16
	Status         Status
	CreatedAt      time.Time
	LastUsedAt     time.Time
	LastDispatchAt time.Time
	Response       []byte
}

type LookupResult struct {
	Status         Status
	Response       []byte
	DispatchNeeded bool
}

type Store struct {
	maxRecords     int
	cacheTTL       time.Duration
	pendingTimeout time.Duration
	items          map[string]*list.Element
	order          *list.List
	mu             sync.Mutex
	dirty          bool
}

type cacheNode struct {
	key   string
	entry Entry
}

type diskEntry struct {
	Key           string `json:"key"`
	Domain        string `json:"domain"`
	QuestionType  uint16 `json:"question_type"`
	QuestionClass uint16 `json:"question_class"`
	Response      string `json:"response"`
	CreatedAt     int64  `json:"created_at"`
	LastUsedAt    int64  `json:"last_used_at"`
}

func New(maxRecords int, cacheTTL time.Duration, pendingTimeout time.Duration) *Store {
	if maxRecords < 1 {
		maxRecords = 1
	}
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}
	if pendingTimeout <= 0 {
		pendingTimeout = 30 * time.Second
	}
	return &Store{
		maxRecords:     maxRecords,
		cacheTTL:       cacheTTL,
		pendingTimeout: pendingTimeout,
		items:          make(map[string]*list.Element, maxRecords),
		order:          list.New(),
	}
}

func BuildKey(domain string, qType uint16, qClass uint16) []byte {
	key := make([]byte, 5+len(domain))
	binary.BigEndian.PutUint16(key[0:2], qType)
	binary.BigEndian.PutUint16(key[2:4], qClass)
	key[4] = 0
	copy(key[5:], domain)
	return key
}

func PatchResponseForQuery(rawResponse []byte, rawQuery []byte) []byte {
	if len(rawResponse) < 2 {
		return rawResponse
	}
	if len(rawQuery) < 2 {
		return rawResponse
	}

	patched := make([]byte, len(rawResponse))
	copy(patched, rawResponse)
	copy(patched[:2], rawQuery[:2])
	if len(rawQuery) >= 4 && len(patched) >= 4 {
		queryFlags := binary.BigEndian.Uint16(rawQuery[2:4])
		responseFlags := binary.BigEndian.Uint16(patched[2:4])
		responseFlags = (responseFlags &^ 0x0110) | (queryFlags & 0x0110)
		binary.BigEndian.PutUint16(patched[2:4], responseFlags)
	}
	return patched
}

func (s *Store) LookupOrCreatePending(cacheKey []byte, domain string, qType uint16, qClass uint16, now time.Time) LookupResult {
	if s == nil || len(cacheKey) == 0 {
		return LookupResult{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(cacheKey)
	if element, ok := s.items[key]; ok {
		node := element.Value.(*cacheNode)
		if !s.isExpired(&node.entry, now) {
			s.touchEntry(&node.entry, now)
			if node.entry.Status == StatusReady {
				s.order.MoveToBack(element)
				return LookupResult{
					Status:   StatusReady,
					Response: PatchResponseForQuery(node.entry.Response, nil),
				}
			}
			if now.Sub(node.entry.LastDispatchAt) >= s.pendingTimeout {
				node.entry.LastDispatchAt = now
				s.dirty = true
				s.order.MoveToBack(element)
				return LookupResult{
					Status:         StatusPending,
					DispatchNeeded: true,
				}
			}
			s.order.MoveToBack(element)
			return LookupResult{Status: StatusPending}
		}

		s.removeElement(element)
	}

	entry := Entry{
		Domain:         domain,
		QuestionType:   qType,
		QuestionClass:  qClass,
		Status:         StatusPending,
		CreatedAt:      now,
		LastUsedAt:     now,
		LastDispatchAt: now,
	}
	element := s.order.PushBack(&cacheNode{key: key, entry: entry})
	s.items[key] = element
	s.dirty = true
	s.evictIfNeeded()
	return LookupResult{
		Status:         StatusPending,
		DispatchNeeded: true,
	}
}

func (s *Store) GetReady(cacheKey []byte, rawQuery []byte, now time.Time) ([]byte, bool) {
	if s == nil || len(cacheKey) == 0 {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	element, ok := s.items[string(cacheKey)]
	if !ok {
		return nil, false
	}

	node := element.Value.(*cacheNode)
	if s.isExpired(&node.entry, now) {
		s.removeElement(element)
		return nil, false
	}
	if node.entry.Status != StatusReady || len(node.entry.Response) == 0 {
		s.touchEntry(&node.entry, now)
		s.order.MoveToBack(element)
		return nil, false
	}

	s.touchEntry(&node.entry, now)
	s.order.MoveToBack(element)
	return PatchResponseForQuery(node.entry.Response, rawQuery), true
}

func (s *Store) SetReady(cacheKey []byte, domain string, qType uint16, qClass uint16, rawResponse []byte, now time.Time) {
	if s == nil || len(cacheKey) == 0 || len(rawResponse) < 2 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(cacheKey)
	normalized := make([]byte, len(rawResponse))
	copy(normalized, rawResponse)
	normalized[0], normalized[1] = 0, 0

	if element, ok := s.items[key]; ok {
		node := element.Value.(*cacheNode)
		node.entry.Domain = domain
		node.entry.QuestionType = qType
		node.entry.QuestionClass = qClass
		node.entry.Status = StatusReady
		if node.entry.CreatedAt.IsZero() {
			node.entry.CreatedAt = now
		}
		node.entry.LastUsedAt = now
		node.entry.Response = normalized
		s.dirty = true
		s.order.MoveToBack(element)
		return
	}

	entry := Entry{
		Domain:        domain,
		QuestionType:  qType,
		QuestionClass: qClass,
		Status:        StatusReady,
		CreatedAt:     now,
		LastUsedAt:    now,
		Response:      normalized,
	}
	element := s.order.PushBack(&cacheNode{key: key, entry: entry})
	s.items[key] = element
	s.dirty = true
	s.evictIfNeeded()
}

func (s *Store) Snapshot(cacheKey []byte) (Entry, bool) {
	if s == nil || len(cacheKey) == 0 {
		return Entry{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	element, ok := s.items[string(cacheKey)]
	if !ok {
		return Entry{}, false
	}
	node := element.Value.(*cacheNode)
	entry := node.entry
	if len(entry.Response) != 0 {
		entry.Response = append([]byte(nil), entry.Response...)
	}
	return entry, true
}

func (s *Store) isExpired(entry *Entry, now time.Time) bool {
	if entry == nil {
		return true
	}
	if entry.Status == StatusPending {
		return false
	}
	return now.Sub(entry.LastUsedAt) >= s.cacheTTL
}

func (s *Store) evictIfNeeded() {
	for len(s.items) > s.maxRecords {
		front := s.order.Front()
		if front == nil {
			return
		}
		s.removeElement(front)
	}
}

func (s *Store) removeElement(element *list.Element) {
	if element == nil {
		return
	}
	node := element.Value.(*cacheNode)
	delete(s.items, node.key)
	s.order.Remove(element)
	s.dirty = true
}

func (s *Store) LoadFromFile(path string, now time.Time) (int, error) {
	if s == nil || path == "" {
		return 0, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var payload []diskEntry
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*list.Element, s.maxRecords)
	s.order.Init()

	loaded := 0
	for _, item := range payload {
		if item.Key == "" || item.Response == "" {
			continue
		}

		keyBytes, err := base64.StdEncoding.DecodeString(item.Key)
		if err != nil || len(keyBytes) == 0 {
			continue
		}
		response, err := base64.StdEncoding.DecodeString(item.Response)
		if err != nil || len(response) < 2 {
			continue
		}

		lastUsedAt := time.Unix(item.LastUsedAt, 0)
		if lastUsedAt.IsZero() {
			continue
		}

		entry := Entry{
			Domain:        item.Domain,
			QuestionType:  item.QuestionType,
			QuestionClass: item.QuestionClass,
			Status:        StatusReady,
			CreatedAt:     time.Unix(item.CreatedAt, 0),
			LastUsedAt:    lastUsedAt,
			Response:      response,
		}
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = lastUsedAt
		}
		if s.isExpired(&entry, now) {
			continue
		}

		key := string(keyBytes)
		element := s.order.PushBack(&cacheNode{key: key, entry: entry})
		s.items[key] = element
		loaded++
	}
	s.evictIfNeeded()
	s.dirty = false
	return loaded, nil
}

func (s *Store) SaveToFile(path string, now time.Time) (int, error) {
	if s == nil || path == "" {
		return 0, nil
	}

	s.mu.Lock()
	s.purgeExpiredLocked(now)
	if !s.dirty {
		s.mu.Unlock()
		return 0, nil
	}

	payload := make([]diskEntry, 0, len(s.items))
	for element := s.order.Front(); element != nil; element = element.Next() {
		node := element.Value.(*cacheNode)
		if node.entry.Status != StatusReady || len(node.entry.Response) < 2 {
			continue
		}
		payload = append(payload, diskEntry{
			Key:           base64.StdEncoding.EncodeToString([]byte(node.key)),
			Domain:        node.entry.Domain,
			QuestionType:  node.entry.QuestionType,
			QuestionClass: node.entry.QuestionClass,
			Response:      base64.StdEncoding.EncodeToString(node.entry.Response),
			CreatedAt:     node.entry.CreatedAt.Unix(),
			LastUsedAt:    node.entry.LastUsedAt.Unix(),
		})
	}
	s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, raw, 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return 0, err
	}

	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return len(payload), nil
}

func (s *Store) touchEntry(entry *Entry, now time.Time) {
	if entry == nil {
		return
	}
	if entry.LastUsedAt.IsZero() || now.Sub(entry.LastUsedAt) >= time.Second {
		entry.LastUsedAt = now
		s.dirty = true
		return
	}
	entry.LastUsedAt = now
}

func (s *Store) purgeExpiredLocked(now time.Time) {
	for element := s.order.Front(); element != nil; {
		next := element.Next()
		node := element.Value.(*cacheNode)
		if s.isExpired(&node.entry, now) {
			s.removeElement(element)
		}
		element = next
	}
}
