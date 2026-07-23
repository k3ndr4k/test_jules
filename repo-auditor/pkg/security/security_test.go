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

func TestParsePomLicenses_EdgeCases(t *testing.T) {
	// Test non-existent file
	report1 := &SecurityReport{}
	parsePomLicenses("does-not-exist.xml", report1)
	if len(report1.CopyleftLicenses) != 0 {
		t.Errorf("Expected 0 copyleft licenses for non-existent file, got %d", len(report1.CopyleftLicenses))
	}

	// Test invalid XML
	tmpDir := t.TempDir()
	invalidXmlPath := filepath.Join(tmpDir, "invalid-pom.xml")
	os.WriteFile(invalidXmlPath, []byte("<project><licenses><license><name>GPL-3.0</name></license>"), 0644) // missing closing tags

	report2 := &SecurityReport{}
	parsePomLicenses(invalidXmlPath, report2)
	if len(report2.CopyleftLicenses) != 0 {
		t.Errorf("Expected 0 copyleft licenses for invalid XML, got %d", len(report2.CopyleftLicenses))
	}

	// Valid XML with copyleft to make sure it works normally
	validXmlPath := filepath.Join(tmpDir, "valid-pom.xml")
	os.WriteFile(validXmlPath, []byte("<project><licenses><license><name>GPL-3.0</name></license></licenses></project>"), 0644)

	report3 := &SecurityReport{}
	parsePomLicenses(validXmlPath, report3)
	if len(report3.CopyleftLicenses) != 2 { // 1 from tag, 1 from heuristic
		t.Errorf("Expected 2 copyleft licenses for valid XML (tag + heuristic), got %d", len(report3.CopyleftLicenses))
	}
}

func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		expected string
	}{
		// Copyleft licenses
		{"Uppercase GPL", "GPL", "RISQUE CRITIQUE (Copyleft)"},
		{"Lowercase GPL", "gpl", "RISQUE CRITIQUE (Copyleft)"},
		{"AGPL", "AGPL", "RISQUE CRITIQUE (Copyleft)"},
		{"LGPL", "LGPL", "RISQUE CRITIQUE (Copyleft)"},
		{"GPL with version", "GPL-3.0", "RISQUE CRITIQUE (Copyleft)"},
		{"GPL inside text", "GNU General Public License (GPL)", "RISQUE CRITIQUE (Copyleft)"},

		// Safe licenses
		{"MIT", "MIT", "Sûr"},
		{"Apache", "Apache-2.0", "Sûr"},
		{"BSD", "BSD", "Sûr"},
		{"Empty string", "", "Sûr"},
		{"Safe mock license", "Safe License", "Sûr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyLicense(tt.license); got != tt.expected {
				t.Errorf("classifyLicense(%q) = %q, want %q", tt.license, got, tt.expected)
			}
		})
	}
}

func TestSecurityReport_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		report   SecurityReport
		expected bool
	}{
		{
			name:     "Empty report",
			report:   SecurityReport{},
			expected: true,
		},
		{
			name:     "Non-empty CriticalCount",
			report:   SecurityReport{CriticalCount: 1},
			expected: false,
		},
		{
			name:     "Non-empty HighCount",
			report:   SecurityReport{HighCount: 1},
			expected: false,
		},
		{
			name:     "Non-empty MediumCount",
			report:   SecurityReport{MediumCount: 1},
			expected: false,
		},
		{
			name:     "Non-empty TopVulns",
			report:   SecurityReport{TopVulns: []Vulnerability{{}}},
			expected: false,
		},
		{
			name:     "Non-empty SecretsAndIaC",
			report:   SecurityReport{SecretsAndIaC: []SecretOrIaC{{}}},
			expected: false,
		},
		{
			name:     "Non-empty GitleaksSecrets",
			report:   SecurityReport{GitleaksSecrets: []GitleaksFinding{{}}},
			expected: false,
		},
		{
			name:     "Non-empty HadolintIssues",
			report:   SecurityReport{HadolintIssues: []HadolintFinding{{}}},
			expected: false,
		},
		{
			name:     "Non-empty KubeLinterIssues",
			report:   SecurityReport{KubeLinterIssues: []KubeLinterFinding{{}}},
			expected: false,
		},
		{
			name:     "Non-empty CopyleftLicenses",
			report:   SecurityReport{CopyleftLicenses: []CopyleftLicense{{}}},
			expected: false,
		},
		{
			name:     "Non-empty CycloComplexities",
			report:   SecurityReport{CycloComplexities: []CycloFinding{{}}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.report.IsEmpty(); got != tt.expected {
				t.Errorf("SecurityReport.IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}
