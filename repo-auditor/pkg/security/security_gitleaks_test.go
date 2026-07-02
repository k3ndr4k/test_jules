package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunGitleaksScan_FindsSecret(t *testing.T) {
	tmpDir := t.TempDir()

	secretContent := `api_key=sk-1234567890abcdef1234567890abcdef`
	err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte(secretContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write dummy file: %v", err)
	}

	report := &SecurityReport{}
	RunGitleaksScan(tmpDir, report)

	if len(report.GitleaksSecrets) == 0 {
		t.Fatalf("Expected at least 1 secret finding, got 0")
	}

	foundKey := false
	for _, sec := range report.GitleaksSecrets {
		if sec.Rule == "generic-api-key" {
			foundKey = true
		}
	}

	if !foundKey {
		t.Errorf("Did not find generic-api-key in Gitleaks findings. Findings: %v", report.GitleaksSecrets)
	}
}

func TestRunGitleaksScan_NoSecrets(t *testing.T) {
	tmpDir := t.TempDir()

	safeContent := `
def my_func():
	print("Hello, world!")
`
	err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte(safeContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write dummy file: %v", err)
	}

	report := &SecurityReport{}
	RunGitleaksScan(tmpDir, report)

	if len(report.GitleaksSecrets) != 0 {
		t.Fatalf("Expected 0 secret findings, got %d", len(report.GitleaksSecrets))
	}
}

func TestRunGitleaksScan_IgnoresDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory, it should be ignored
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	report := &SecurityReport{}
	RunGitleaksScan(tmpDir, report)

	if len(report.GitleaksSecrets) != 0 {
		t.Fatalf("Expected 0 secret findings, got %d", len(report.GitleaksSecrets))
	}
}
