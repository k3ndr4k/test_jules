package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunKubeLinterScan_BinaryNotFound(t *testing.T) {
	lookPathCache.Store("kube-linter", struct {
		path string
		err  error
	}{"", errors.New("not found")})
	defer lookPathCache.Delete("kube-linter")

	report := &SecurityReport{}
	RunKubeLinterScan(".", "myrepo", report)

	if !report.KubeLinterSkipped {
		t.Errorf("Expected KubeLinterSkipped to be true")
	}
}

func TestRunKubeLinterScan_Success(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "mock-kube-linter.sh")
	scriptContent := `#!/bin/sh
echo '{"Reports": [{"FilePath": "deployment.yaml", "Diagnostic": {"Message": "mock message"}, "Check": "probe-missing", "Remediation": "mock remediation"}]}'
`
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		t.Fatalf("Failed to write mock script: %v", err)
	}

	lookPathCache.Store("kube-linter", struct {
		path string
		err  error
	}{scriptPath, nil})
	defer lookPathCache.Delete("kube-linter")

	report := &SecurityReport{}
	RunKubeLinterScan(".", "myrepo", report)

	if report.KubeLinterSkipped {
		t.Errorf("Expected KubeLinterSkipped to be false")
	}

	if len(report.KubeLinterIssues) != 1 {
		t.Fatalf("Expected 1 issue, got %d", len(report.KubeLinterIssues))
	}

	issue := report.KubeLinterIssues[0]
	if issue.Message != "mock message" {
		t.Errorf("Expected message 'mock message', got '%s'", issue.Message)
	}
	if issue.Check != "probe-missing" {
		t.Errorf("Expected check 'probe-missing', got '%s'", issue.Check)
	}
}
