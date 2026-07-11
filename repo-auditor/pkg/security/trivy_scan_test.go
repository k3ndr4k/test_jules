package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunTrivyScan_Success(t *testing.T) {
	mockScript := `#!/bin/sh
cat << 'EOF' > "$5"
{
  "Results": [
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Misconfigurations": [
        {
          "Type": "Dockerfile",
          "ID": "DS001",
          "Title": "Run as root",
          "Description": "Running as root is bad",
          "Severity": "HIGH"
        }
      ],
      "Secrets": [
        {
          "RuleID": "AWS-01",
          "Category": "AWS",
          "Title": "AWS Access Key",
          "Severity": "CRITICAL"
        }
      ]
    },
    {
      "Target": "package.json",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-1234",
          "PkgName": "express",
          "Severity": "CRITICAL",
          "Title": "RCE in express",
          "Description": "Remote Code Execution"
        },
        {
          "VulnerabilityID": "CVE-2021-1235",
          "PkgName": "lodash",
          "Severity": "HIGH",
          "Title": "Prototype Pollution",
          "Description": "Prototype Pollution in lodash"
        },
        {
          "VulnerabilityID": "CVE-2021-1236",
          "PkgName": "react",
          "Severity": "MEDIUM",
          "Title": "XSS in react",
          "Description": "Cross Site Scripting"
        }
      ]
    }
  ]
}
EOF
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "trivy")
	err := os.WriteFile(mockPath, []byte(mockScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create mock script: %v", err)
	}

	lookPathCache.Store("trivy", struct {
		path string
		err  error
	}{path: mockPath, err: nil})
	defer lookPathCache.Delete("trivy")

	report := &SecurityReport{}

	RunTrivyScan(tmpDir, report)

	if report.CriticalCount != 1 {
		t.Errorf("Expected 1 critical vulnerability, got %d", report.CriticalCount)
	}
	if report.HighCount != 1 {
		t.Errorf("Expected 1 high vulnerability, got %d", report.HighCount)
	}
	if report.MediumCount != 1 {
		t.Errorf("Expected 1 medium vulnerability, got %d", report.MediumCount)
	}

	if len(report.TopVulns) != 3 {
		t.Errorf("Expected 3 top vulnerabilities, got %d", len(report.TopVulns))
	} else {
		if report.TopVulns[0].VulnerabilityID != "CVE-2021-1234" {
			t.Errorf("Expected first top vuln to be CVE-2021-1234, got %s", report.TopVulns[0].VulnerabilityID)
		}
	}

	if len(report.SecretsAndIaC) != 2 {
		t.Errorf("Expected 2 SecretsAndIaC, got %d", len(report.SecretsAndIaC))
	} else {
		foundSecret := false
		foundMisconfig := false
		for _, s := range report.SecretsAndIaC {
			if s.Class == "Secret" && s.Title == "AWS Access Key" {
				foundSecret = true
			}
			if s.Class == "IaC/Config" && s.Title == "Run as root" {
				foundMisconfig = true
			}
		}
		if !foundSecret {
			t.Errorf("Expected to find AWS Access Key secret")
		}
		if !foundMisconfig {
			t.Errorf("Expected to find Run as root misconfiguration")
		}
	}
}

func TestRunTrivyScan_Skipped(t *testing.T) {
	lookPathCache.Store("trivy", struct {
		path string
		err  error
	}{path: "", err: os.ErrNotExist})
	defer lookPathCache.Delete("trivy")

	report := &SecurityReport{}
	tmpDir := t.TempDir()

	RunTrivyScan(tmpDir, report)

	if report.CriticalCount != 0 || report.HighCount != 0 || report.MediumCount != 0 {
		t.Errorf("Expected 0 counts, got %d %d %d", report.CriticalCount, report.HighCount, report.MediumCount)
	}
	if len(report.TopVulns) != 0 {
		t.Errorf("Expected 0 top vulnerabilities, got %d", len(report.TopVulns))
	}
	if len(report.SecretsAndIaC) != 0 {
		t.Errorf("Expected 0 SecretsAndIaC, got %d", len(report.SecretsAndIaC))
	}
}

func TestRunTrivyScan_InvalidJSON(t *testing.T) {
	mockScript := `#!/bin/sh
echo 'invalid json output' > "$5"
`
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "trivy")
	err := os.WriteFile(mockPath, []byte(mockScript), 0755)
	if err != nil {
		t.Fatalf("Failed to create mock script: %v", err)
	}

	lookPathCache.Store("trivy", struct {
		path string
		err  error
	}{path: mockPath, err: nil})
	defer lookPathCache.Delete("trivy")

	report := &SecurityReport{}

	RunTrivyScan(tmpDir, report)

	if report.CriticalCount != 0 || report.HighCount != 0 || report.MediumCount != 0 {
		t.Errorf("Expected 0 counts due to invalid JSON, got %d %d %d", report.CriticalCount, report.HighCount, report.MediumCount)
	}
	if len(report.TopVulns) != 0 {
		t.Errorf("Expected 0 top vulnerabilities, got %d", len(report.TopVulns))
	}
	if len(report.SecretsAndIaC) != 0 {
		t.Errorf("Expected 0 SecretsAndIaC, got %d", len(report.SecretsAndIaC))
	}
}
