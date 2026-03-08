package githubapp

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileDeliveryStoreDedupesAndPersists(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "deliveries.json")
	store := NewFileDeliveryStore(storePath, 24*time.Hour)

	started, err := store.TryStart("delivery-1")
	if err != nil {
		t.Fatalf("TryStart returned error: %v", err)
	}
	if !started {
		t.Fatalf("expected first delivery to start")
	}

	started, err = store.TryStart("delivery-1")
	if err != nil {
		t.Fatalf("TryStart returned error: %v", err)
	}
	if started {
		t.Fatalf("expected duplicate delivery to be skipped")
	}

	if err := store.MarkDone("delivery-1"); err != nil {
		t.Fatalf("MarkDone returned error: %v", err)
	}

	reloaded := NewFileDeliveryStore(storePath, 24*time.Hour)
	started, err = reloaded.TryStart("delivery-1")
	if err != nil {
		t.Fatalf("TryStart on reloaded store returned error: %v", err)
	}
	if started {
		t.Fatalf("expected persisted delivery to remain deduped")
	}
}

func TestFileDeliveryStoreExpiresOldEntries(t *testing.T) {
	store := NewFileDeliveryStore(filepath.Join(t.TempDir(), "deliveries.json"), time.Second)
	store.entries["old"] = deliveryRecord{State: "done", UpdatedAt: time.Now().Add(-2 * time.Second).Unix()}
	store.entries["new"] = deliveryRecord{State: "done", UpdatedAt: time.Now().Unix()}
	store.loaded = true

	store.cleanupExpired(time.Now())

	if _, ok := store.entries["old"]; ok {
		t.Fatalf("old entry should have been removed")
	}
	if _, ok := store.entries["new"]; !ok {
		t.Fatalf("new entry should still exist")
	}
}
