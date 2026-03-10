package githubapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type schedulerStateStore struct {
	path string

	mu   sync.Mutex
	data schedulerState
}

type schedulerState struct {
	Repositories map[string]scheduledRepositoryState `json:"repositories"`
}

type scheduledRepositoryState struct {
	NextRunAt              time.Time                  `json:"next_run_at,omitempty"`
	ScheduleKey            string                     `json:"schedule_key,omitempty"`
	LastScanAt             time.Time                  `json:"last_scan_at,omitempty"`
	LastFindingCount       int                        `json:"last_finding_count,omitempty"`
	LastFindingsBySeverity map[string]int             `json:"last_findings_by_severity,omitempty"`
	OpenPR                 *trackedRemediationPRState `json:"open_pr,omitempty"`
}

type trackedRemediationPRState struct {
	Number     int       `json:"number,omitempty"`
	URL        string    `json:"url,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

func newSchedulerStateStore(path string) (*schedulerStateStore, error) {
	store := &schedulerStateStore{
		path: path,
		data: schedulerState{Repositories: map[string]scheduledRepositoryState{}},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *schedulerStateStore) Get(repoKey string) scheduledRepositoryState {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneScheduledRepositoryState(store.data.Repositories[repoKey])
}

func (store *schedulerStateStore) Upsert(repoKey, scheduleKey string, nextRunAt time.Time) error {
	if repoKey == "" {
		return errors.New("repository key is empty")
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if store.data.Repositories == nil {
		store.data.Repositories = map[string]scheduledRepositoryState{}
	}
	current := store.data.Repositories[repoKey]
	current.NextRunAt = nextRunAt.UTC()
	current.ScheduleKey = scheduleKey
	store.data.Repositories[repoKey] = current
	return store.persistLocked()
}

func (store *schedulerStateStore) Update(repoKey string, mutate func(*scheduledRepositoryState)) error {
	if repoKey == "" {
		return errors.New("repository key is empty")
	}
	if mutate == nil {
		return nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if store.data.Repositories == nil {
		store.data.Repositories = map[string]scheduledRepositoryState{}
	}
	current := cloneScheduledRepositoryState(store.data.Repositories[repoKey])
	mutate(&current)
	store.data.Repositories[repoKey] = current
	return store.persistLocked()
}

func (store *schedulerStateStore) Snapshot() map[string]scheduledRepositoryState {
	store.mu.Lock()
	defer store.mu.Unlock()

	snapshot := make(map[string]scheduledRepositoryState, len(store.data.Repositories))
	for key, value := range store.data.Repositories {
		snapshot[key] = cloneScheduledRepositoryState(value)
	}
	return snapshot
}

func (store *schedulerStateStore) load() error {
	store.mu.Lock()
	defer store.mu.Unlock()

	data, err := os.ReadFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read scheduler state %s: %w", store.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &store.data); err != nil {
		return fmt.Errorf("decode scheduler state %s: %w", store.path, err)
	}
	if store.data.Repositories == nil {
		store.data.Repositories = map[string]scheduledRepositoryState{}
	}
	return nil
}

func (store *schedulerStateStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("create scheduler state directory: %w", err)
	}
	data, err := json.MarshalIndent(store.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode scheduler state: %w", err)
	}
	if err := os.WriteFile(store.path, data, 0o644); err != nil {
		return fmt.Errorf("write scheduler state %s: %w", store.path, err)
	}
	return nil
}

func cloneScheduledRepositoryState(state scheduledRepositoryState) scheduledRepositoryState {
	cloned := state
	if len(state.LastFindingsBySeverity) > 0 {
		cloned.LastFindingsBySeverity = make(map[string]int, len(state.LastFindingsBySeverity))
		for severity, count := range state.LastFindingsBySeverity {
			cloned.LastFindingsBySeverity[severity] = count
		}
	}
	if state.OpenPR != nil {
		openPR := *state.OpenPR
		cloned.OpenPR = &openPR
	}
	return cloned
}
