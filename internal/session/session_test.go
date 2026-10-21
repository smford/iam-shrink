package session

import (
	"os"
	"testing"
	"time"

	"github.com/smford/iam-shrink/internal/csm"
)

func TestSessionManagerLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	mgr, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// 1. Initial state: no session
	state, err := mgr.LoadSession()
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if state != nil {
		t.Errorf("Expected nil session, got %+v", state)
	}

	// 2. Save session
	eventsFile := tempDir + "/events.jsonl"
	initState := SessionState{
		PID:        os.Getpid(),
		CSMPort:    31000,
		ProxyPort:  31001,
		EventsFile: eventsFile,
		StartTime:  time.Now(),
	}

	if err := mgr.SaveSession(initState); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	// 3. Load session and verify running
	loaded, err := mgr.LoadSession()
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	if loaded == nil || loaded.CSMPort != 31000 {
		t.Errorf("Unexpected loaded session: %+v", loaded)
	}

	if !mgr.IsRunning(loaded) {
		t.Errorf("Expected current PID %d to be recognized as running", os.Getpid())
	}

	// 4. Append and read events
	evt1 := csm.Event{Service: "S3", Api: "GetObject"}
	evt2 := csm.Event{Service: "DynamoDB", Api: "PutItem"}
	if err := mgr.AppendEvent(eventsFile, evt1); err != nil {
		t.Fatalf("AppendEvent failed: %v", err)
	}
	if err := mgr.AppendEvent(eventsFile, evt2); err != nil {
		t.Fatalf("AppendEvent failed: %v", err)
	}

	events, err := mgr.ReadEvents(eventsFile)
	if err != nil {
		t.Fatalf("ReadEvents failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}
}
