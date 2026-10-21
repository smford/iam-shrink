package vscode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// TaskDefinition represents a VS Code shell task.
type TaskDefinition struct {
	Label        string            `json:"label"`
	Type         string            `json:"type"`
	Command      string            `json:"command"`
	Group        string            `json:"group"`
	Presentation map[string]string `json:"presentation"`
}

// TasksFile represents the .vscode/tasks.json file structure.
type TasksFile struct {
	Version string           `json:"version"`
	Tasks   []TaskDefinition `json:"tasks"`
}

// GenerateTasksConfig returns a configured VS Code tasks structure for iam-shrink.
func GenerateTasksConfig(testCmd string) TasksFile {
	if testCmd == "" {
		testCmd = "go test ./..."
	}

	return TasksFile{
		Version: "2.0.0",
		Tasks: []TaskDefinition{
			{
				Label:   "iam-shrink: Run Tests & Generate Terraform Policy",
				Type:    "shell",
				Command: fmt.Sprintf("iam-shrink run --format=tf --strict-arns -- %s", testCmd),
				Group:   "test",
				Presentation: map[string]string{
					"reveal": "always",
					"panel":  "new",
				},
			},
			{
				Label:   "iam-shrink: Run Tests & Generate AWS CDK Policy",
				Type:    "shell",
				Command: fmt.Sprintf("iam-shrink run --format=cdk --out=iam_policy.ts -- %s", testCmd),
				Group:   "test",
				Presentation: map[string]string{
					"reveal": "always",
					"panel":  "new",
				},
			},
			{
				Label:   "iam-shrink: Run Tests & Generate IAM JSON",
				Type:    "shell",
				Command: fmt.Sprintf("iam-shrink run --format=json -- %s", testCmd),
				Group:   "test",
				Presentation: map[string]string{
					"reveal": "always",
					"panel":  "new",
				},
			},
		},
	}
}

// WriteTasksFile creates .vscode/tasks.json in the specified target root directory.
func WriteTasksFile(targetDir, testCmd string) (string, error) {
	dotVSCode := filepath.Join(targetDir, ".vscode")
	if err := os.MkdirAll(dotVSCode, 0755); err != nil {
		return "", fmt.Errorf("creating .vscode directory: %w", err)
	}

	tasksFile := filepath.Join(dotVSCode, "tasks.json")
	cfg := GenerateTasksConfig(testCmd)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}

	return tasksFile, os.WriteFile(tasksFile, append(data, '\n'), 0644)
}
