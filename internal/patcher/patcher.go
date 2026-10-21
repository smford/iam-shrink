package patcher

import (
	"fmt"
	"os"
	"strings"
)

// PatchOptions configures in-place Terraform patching.
type PatchOptions struct {
	FilePath     string
	TargetName   string // e.g. "generated" or "my_policy"; if empty, matches first data "aws_iam_policy_document"
	NewHCL       string
	CreateBackup bool
}

// PatchTerraformFile updates an existing .tf file in-place with new HCL statements.
func PatchTerraformFile(opts PatchOptions) error {
	data, err := os.ReadFile(opts.FilePath)
	if err != nil {
		return fmt.Errorf("reading terraform file %s: %w", opts.FilePath, err)
	}

	content := string(data)

	if opts.CreateBackup {
		backupPath := opts.FilePath + ".bak"
		if err := os.WriteFile(backupPath, data, 0644); err != nil {
			return fmt.Errorf("creating backup file %s: %w", backupPath, err)
		}
	}

	updated, err := PatchTerraformContent(content, opts.TargetName, opts.NewHCL)
	if err != nil {
		return err
	}

	return os.WriteFile(opts.FilePath, []byte(updated), 0644)
}

// PatchTerraformContent replaces the targeted data aws_iam_policy_document block in content.
func PatchTerraformContent(content, targetName, newHCL string) (string, error) {
	newHCL = strings.TrimSpace(newHCL) + "\n"

	prefixPattern := "data \"aws_iam_policy_document\" "
	if targetName != "" {
		prefixPattern += fmt.Sprintf("%q", targetName)
	}

	idx := strings.Index(content, prefixPattern)
	if idx == -1 {
		// If not found, append cleanly to end of file
		var sb strings.Builder
		sb.WriteString(strings.TrimRight(content, "\n"))
		sb.WriteString("\n\n")
		sb.WriteString(newHCL)
		return sb.String(), nil
	}

	// Find the opening brace
	braceOpen := strings.Index(content[idx:], "{")
	if braceOpen == -1 {
		return "", fmt.Errorf("malformed block: opening brace not found for %s", prefixPattern)
	}
	startPos := idx
	blockStart := idx + braceOpen

	// Match balanced braces to find end of block
	depth := 0
	endPos := -1
	for i := blockStart; i < len(content); i++ {
		if content[i] == '{' {
			depth++
		} else if content[i] == '}' {
			depth--
			if depth == 0 {
				endPos = i + 1
				break
			}
		}
	}

	if endPos == -1 {
		return "", fmt.Errorf("malformed block: matching closing brace not found")
	}

	var sb strings.Builder
	sb.WriteString(content[:startPos])
	sb.WriteString(newHCL)
	if endPos < len(content) {
		sb.WriteString(content[endPos:])
	}

	return sb.String(), nil
}
