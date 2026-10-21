package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/smford/iam-shrink/internal/csm"
)

// SessionState records metadata for an active iam-shrink background session.
type SessionState struct {
	PID        int       `json:"pid"`
	CSMPort    int       `json:"csm_port"`
	ProxyPort  int       `json:"proxy_port,omitempty"`
	EventsFile string    `json:"events_file"`
	StartTime  time.Time `json:"start_time"`
}

// Manager handles the lifecycle of background daemon sessions.
type Manager struct {
	baseDir string
}

// NewManager creates a session manager. If baseDir is empty, defaults to ~/.iam-shrink.
func NewManager(baseDir string) (*Manager, error) {
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("getting user home directory: %w", err)
		}
		baseDir = filepath.Join(home, ".iam-shrink")
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("creating session directory %s: %w", baseDir, err)
	}

	return &Manager{baseDir: baseDir}, nil
}

func (m *Manager) sessionFilePath() string {
	return filepath.Join(m.baseDir, "session.json")
}

// SaveSession writes the session state to disk.
func (m *Manager) SaveSession(state SessionState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.sessionFilePath(), data, 0600)
}

// LoadSession reads active session state from disk.
func (m *Manager) LoadSession() (*SessionState, error) {
	data, err := os.ReadFile(m.sessionFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No active session
		}
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing session file: %w", err)
	}

	return &state, nil
}

// IsRunning checks if the session process is alive.
func (m *Manager) IsRunning(state *SessionState) bool {
	if state == nil || state.PID <= 0 {
		return false
	}

	process, err := os.FindProcess(state.PID)
	if err != nil {
		return false
	}

	// On Unix, sending signal 0 checks for process existence without killing it
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// AppendEvent writes a captured CSM event to the session events file.
func (m *Manager) AppendEvent(eventsFile string, evt csm.Event) error {
	f, err := os.OpenFile(eventsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = f.Write(data)
	return err
}

// ReadEvents reads all captured events recorded during the session.
func (m *Manager) ReadEvents(eventsFile string) ([]csm.Event, error) {
	data, err := os.ReadFile(eventsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var events []csm.Event
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var evt csm.Event
		if err := json.Unmarshal(line, &evt); err == nil {
			if evt.Service != "" && evt.Api != "" {
				events = append(events, evt)
			}
		}
	}
	return events, nil
}

// StopSession sends a SIGTERM to the session process and removes the session file.
func (m *Manager) StopSession() (*SessionState, error) {
	state, err := m.LoadSession()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, fmt.Errorf("no active session found")
	}

	if m.IsRunning(state) {
		p, err := os.FindProcess(state.PID)
		if err == nil {
			_ = p.Signal(syscall.SIGTERM)
			// Wait briefly for process to exit
			time.Sleep(200 * time.Millisecond)
		}
	}

	_ = os.Remove(m.sessionFilePath())
	return state, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
