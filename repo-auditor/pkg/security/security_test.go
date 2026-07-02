package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicenseScanFromFixture(t *testing.T) {
	fixturePath, _ := filepath.Abs("../../../tests/fixtures/java-project/pom.xml")

	report := &SecurityReport{}
	RunLicenseScan(fixturePath, "java-project", true, report)

	if len(report.CopyleftLicenses) == 0 {
		t.Fatalf("Expected at least one license finding, got 0")
	}

	foundGPL := false
	for _, lic := range report.CopyleftLicenses {
		if lic.License == "GPL-3.0" && lic.Status == "RISQUE CRITIQUE (Copyleft)" {
			foundGPL = true
		}
	}

	if !foundGPL {
		t.Errorf("Expected to find GPL-3.0 as Copyleft, findings: %v", report.CopyleftLicenses)
	}
}

func TestKubeLinterJsonParsingFromFixture(t *testing.T) {
	fixturePath, _ := filepath.Abs("../../../tests/fixtures/helm-chart/kube-linter-report.json")

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture JSON: %v", err)
	}

	report := &SecurityReport{}
	ParseKubeLinterReport(data, "helm-chart", report)

	if len(report.KubeLinterIssues) != 4 {
		t.Errorf("Expected 4 issues (2 probes, 2 limits), got %d", len(report.KubeLinterIssues))
	}
}

func TestGocycloASTFallbackFromFixture(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/go-complex")

	report := &SecurityReport{}

	RunGocycloScan(fixtureDir, "go-complex", report)

	if len(report.CycloComplexities) == 0 {
		t.Fatalf("Expected cyclomatic complexity findings, got 0")
	}

	foundComplex := false
	for _, c := range report.CycloComplexities {
		if strings.Contains(c.Function, "UltraComplexFunction") {
			if c.Score < 15 {
				t.Errorf("Expected UltraComplexFunction to have score > 15, got %d", c.Score)
			}
			foundComplex = true
		}
	}

	if !foundComplex {
		t.Errorf("Did not find 'UltraComplexFunction' in complexities")
	}
}

func TestRunHadolintScan_Success(t *testing.T) {
	mockScript := `#!/bin/sh
echo '[{"line": 12, "code": "DL3008", "level": "warning", "message": "Pin versions in apt get install"}]'
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "hadolint")
	err := os.WriteFile(mockPath, []byte(mockScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create mock script: %v", err)
	}

	lookPathCache.Store("hadolint", struct {
		path string
		err  error
	}{path: mockPath, err: nil})
	defer lookPathCache.Delete("hadolint")

	report := &SecurityReport{}
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	os.WriteFile(dockerfilePath, []byte("FROM ubuntu:latest\nRUN apt-get install curl"), 0644)

	RunHadolintScan(dockerfilePath, "test-repo", report)

	if report.HadolintSkipped {
		t.Errorf("Expected HadolintSkipped to be false")
	}

	if len(report.HadolintIssues) != 1 {
		t.Fatalf("Expected 1 issue, got %d", len(report.HadolintIssues))
	}

	issue := report.HadolintIssues[0]
	if issue.Line != 12 || issue.Code != "DL3008" || issue.Level != "warning" {
		t.Errorf("Unexpected issue details: %+v", issue)
	}
}

func TestRunHadolintScan_Skipped(t *testing.T) {
	lookPathCache.Store("hadolint", struct {
		path string
		err  error
	}{path: "", err: os.ErrNotExist})
	defer lookPathCache.Delete("hadolint")

	report := &SecurityReport{}
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	os.WriteFile(dockerfilePath, []byte("FROM ubuntu:latest"), 0644)

	RunHadolintScan(dockerfilePath, "test-repo", report)

	if !report.HadolintSkipped {
		t.Errorf("Expected HadolintSkipped to be true")
	}

	if len(report.HadolintIssues) != 0 {
		t.Fatalf("Expected 0 issues, got %d", len(report.HadolintIssues))
	}
}

func TestRunHadolintScan_InvalidJSON(t *testing.T) {
	mockScript := `#!/bin/sh
echo 'invalid json output'
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "hadolint")
	err := os.WriteFile(mockPath, []byte(mockScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create mock script: %v", err)
	}

	lookPathCache.Store("hadolint", struct {
		path string
		err  error
	}{path: mockPath, err: nil})
	defer lookPathCache.Delete("hadolint")

	report := &SecurityReport{}
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	os.WriteFile(dockerfilePath, []byte("FROM ubuntu:latest\nRUN apt-get install curl"), 0644)

	RunHadolintScan(dockerfilePath, "test-repo", report)

	if report.HadolintSkipped {
		t.Errorf("Expected HadolintSkipped to be false")
	}

	if len(report.HadolintIssues) != 0 {
		t.Fatalf("Expected 0 issues due to invalid JSON, got %d", len(report.HadolintIssues))
	}
}
