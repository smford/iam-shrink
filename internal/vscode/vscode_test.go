package vscode

import (
	"os"
	"strings"
	"testing"
)

func TestWriteTasksFile(t *testing.T) {
	tempDir := t.TempDir()
	tasksPath, err := WriteTasksFile(tempDir, "pytest tests/")
	if err != nil {
		t.Fatalf("WriteTasksFile failed: %v", err)
	}

	data, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "iam-shrink run --format=tf") {
		t.Errorf("Expected iam-shrink run command in tasks.json, got:\n%s", content)
	}
	if !strings.Contains(content, "pytest tests/") {
		t.Errorf("Expected pytest command in tasks.json")
	}
}
