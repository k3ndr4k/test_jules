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
