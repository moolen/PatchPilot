package githubapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type DeliveryStore interface {
	TryStart(deliveryID string) (bool, error)
	MarkDone(deliveryID string) error
}

type FileDeliveryStore struct {
	path string
	ttl  time.Duration

	mu      sync.Mutex
	loaded  bool
	entries map[string]deliveryRecord
}

type deliveryRecord struct {
	State     string `json:"state"`
	UpdatedAt int64  `json:"updated_at_unix"`
}

func NewFileDeliveryStore(path string, ttl time.Duration) *FileDeliveryStore {
	return &FileDeliveryStore{
		path:    path,
		ttl:     ttl,
		entries: map[string]deliveryRecord{},
	}
}

func (store *FileDeliveryStore) TryStart(deliveryID string) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.load(); err != nil {
		return false, err
	}
	store.cleanupExpired(time.Now().UTC())
	if _, exists := store.entries[deliveryID]; exists {
		return false, nil
	}
	store.entries[deliveryID] = deliveryRecord{
		State:     "processing",
		UpdatedAt: time.Now().UTC().Unix(),
	}
	return true, store.persist()
}

func (store *FileDeliveryStore) MarkDone(deliveryID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.load(); err != nil {
		return err
	}
	if _, exists := store.entries[deliveryID]; !exists {
		return nil
	}
	store.entries[deliveryID] = deliveryRecord{
		State:     "done",
		UpdatedAt: time.Now().UTC().Unix(),
	}
	return store.persist()
}

func (store *FileDeliveryStore) load() error {
	if store.loaded {
		return nil
	}
	store.loaded = true

	data, err := os.ReadFile(store.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read delivery store: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &store.entries); err != nil {
		return fmt.Errorf("decode delivery store: %w", err)
	}
	return nil
}

func (store *FileDeliveryStore) persist() error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("create delivery store dir: %w", err)
	}
	data, err := json.MarshalIndent(store.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal delivery store: %w", err)
	}
	tempPath := store.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return fmt.Errorf("write delivery store temp file: %w", err)
	}
	if err := os.Rename(tempPath, store.path); err != nil {
		return fmt.Errorf("replace delivery store: %w", err)
	}
	return nil
}

func (store *FileDeliveryStore) cleanupExpired(now time.Time) {
	if store.ttl <= 0 {
		return
	}
	threshold := now.Add(-store.ttl).Unix()
	for deliveryID, entry := range store.entries {
		if entry.UpdatedAt < threshold {
			delete(store.entries, deliveryID)
		}
	}
}
