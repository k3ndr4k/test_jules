package security

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type SecurityReport struct {
	CriticalCount    int
	HighCount        int
	MediumCount      int
	TopVulns         []Vulnerability
	SecretsAndIaC    []SecretOrIaC
	HadolintSkipped  bool
	KubeLinterSkipped bool
	GitleaksSecrets  []GitleaksFinding
	HadolintIssues   []HadolintFinding
	KubeLinterIssues []KubeLinterFinding
	CopyleftLicenses []CopyleftLicense
}

type Vulnerability struct {
	PkgName         string
	VulnerabilityID string
	Severity        string
	Title           string
	Description     string
}

type SecretOrIaC struct {
	Target string
	Class  string
	Title  string
}

type GitleaksFinding struct {
	File   string
	Rule   string
	Secret string
}

type HadolintFinding struct {
	File     string
	Line     int
	Code     string
	Level    string
	Message  string
}

type KubeLinterFinding struct {
	File    string
	Check   string
	Message string
}

type CopyleftLicense struct {
	File       string
	Dependency string
	License    string
}

type TrivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
			Description     string `json:"Description"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			Type        string `json:"Type"`
			ID          string `json:"ID"`
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Severity    string `json:"Severity"`
		} `json:"Misconfigurations"`
		Secrets []struct {
			RuleID   string `json:"RuleID"`
			Category string `json:"Category"`
			Title    string `json:"Title"`
			Severity string `json:"Severity"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func RunTrivyScan(targetDir string, report *SecurityReport) {
	_, err := exec.LookPath("trivy")
	if err != nil {
		return
	}

	reportFile := filepath.Join(targetDir, "trivy_report.json")
	cmd := exec.Command("trivy", "fs", "--format", "json", "--output", reportFile, ".")
	cmd.Dir = targetDir
	cmd.Run()

	defer os.Remove(reportFile)

	data, err := os.ReadFile(reportFile)
	if err != nil {
		return
	}

	var trivyOut TrivyOutput
	if err := json.Unmarshal(data, &trivyOut); err == nil {
		parseTrivyReport(&trivyOut, report)
	}
}

func parseTrivyReport(trivyOut *TrivyOutput, rep *SecurityReport) {
	var allVulns []Vulnerability

	for _, result := range trivyOut.Results {
		if result.Class == "secret" || result.Class == "config" {
			for _, sec := range result.Secrets {
				rep.SecretsAndIaC = append(rep.SecretsAndIaC, SecretOrIaC{
					Target: result.Target,
					Class:  "Secret",
					Title:  sec.Title,
				})
			}
			for _, misconf := range result.Misconfigurations {
				rep.SecretsAndIaC = append(rep.SecretsAndIaC, SecretOrIaC{
					Target: result.Target,
					Class:  "IaC/Config",
					Title:  misconf.Title,
				})
			}
		}

		for _, v := range result.Vulnerabilities {
			vuln := Vulnerability{
				PkgName:         v.PkgName,
				VulnerabilityID: v.VulnerabilityID,
				Severity:        v.Severity,
				Title:           v.Title,
				Description:     v.Description,
			}
			allVulns = append(allVulns, vuln)

			switch v.Severity {
			case "CRITICAL":
				rep.CriticalCount++
			case "HIGH":
				rep.HighCount++
			case "MEDIUM":
				rep.MediumCount++
			}
		}
	}

	severityScore := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
	sort.SliceStable(allVulns, func(i, j int) bool {
		return severityScore[allVulns[i].Severity] > severityScore[allVulns[j].Severity]
	})

	seen := make(map[string]bool)
	for _, v := range allVulns {
		if len(rep.TopVulns) >= 5 {
			break
		}
		if !seen[v.VulnerabilityID] {
			rep.TopVulns = append(rep.TopVulns, v)
			seen[v.VulnerabilityID] = true
		}
	}
}

func RunGitleaksScan(repoPath string, reportOut *SecurityReport) {
	viperCfg := config.ViperConfig{}
	viperCfg.Translate()
	cfg, _ := viperCfg.Translate()
	detector := detect.NewDetector(cfg)
	scanTargets := make(chan sources.ScanTarget, 100)

	go func() {
		filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				if info.Mode().IsRegular() {
					scanTargets <- sources.ScanTarget{Path: path}
				}
			}
			return nil
		})
		close(scanTargets)
	}()

	findings, _ := detector.DetectFiles(scanTargets)

	for _, finding := range findings {
		reportOut.GitleaksSecrets = append(reportOut.GitleaksSecrets, GitleaksFinding{
			File:   finding.File,
			Rule:   finding.RuleID,
			Secret: finding.Description,
		})
	}
}

func RunHadolintScan(dockerfilePath string, repoName string, report *SecurityReport) {
	_, err := exec.LookPath("hadolint")
	if err != nil {
		report.HadolintSkipped = true
		return
	}

	cmd := exec.Command("hadolint", "--format", "json", dockerfilePath)
	out, _ := cmd.Output()

	var issues []struct {
		Line    int    `json:"line"`
		Code    string `json:"code"`
		Level   string `json:"level"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(out, &issues); err == nil {
		for _, issue := range issues {
			report.HadolintIssues = append(report.HadolintIssues, HadolintFinding{
				File:    filepath.Join(repoName, filepath.Base(dockerfilePath)),
				Line:    issue.Line,
				Code:    issue.Code,
				Level:   issue.Level,
				Message: issue.Message,
			})
		}
	}
}

func RunKubeLinterScan(repoPath string, repoName string, report *SecurityReport) {
	_, err := exec.LookPath("kube-linter")
	if err != nil {
		report.KubeLinterSkipped = true
		return
	}

	cmd := exec.Command("kube-linter", "lint", "--format", "json", repoPath)
	out, _ := cmd.Output()

	var klOutput struct {
		Reports []struct {
			FilePath   string `json:"FilePath"`
			Diagnostic struct {
				Message string `json:"Message"`
			} `json:"Diagnostic"`
			Check string `json:"Check"`
		} `json:"Reports"`
	}

	if err := json.Unmarshal(out, &klOutput); err == nil {
		for _, rep := range klOutput.Reports {
			checkName := strings.ToLower(rep.Check)
			if strings.Contains(checkName, "probe") || strings.Contains(checkName, "limit") || strings.Contains(checkName, "request") {
				report.KubeLinterIssues = append(report.KubeLinterIssues, KubeLinterFinding{
					File:    filepath.Join(repoName, filepath.Base(rep.FilePath)),
					Check:   rep.Check,
					Message: rep.Diagnostic.Message,
				})
			}
		}
	}
}

func RunLicenseScan(filePath string, repoName string, isPom bool, report *SecurityReport) {
	// Simple heuristic extraction: looks for copyleft license identifiers inside dependency definitions.
	// In reality, this requires a dependency graph and API lookups.
	// For this local scanner, we use a basic regex search simulating SCA.
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return
	}
	content := string(data)

	// Very rudimentary heuristic: Search for common copyleft words. If found in file, flag it.
	// A robust solution uses Trivy or similar.
	copyleftRegex := regexp.MustCompile(`(?i)(GPL|AGPL|GNU General Public License)`)
	matches := copyleftRegex.FindAllStringSubmatch(content, -1)

	if len(matches) > 0 {
		seen := make(map[string]bool)
		for _, match := range matches {
			lic := strings.ToUpper(match[1])
			if !seen[lic] {
				seen[lic] = true
				report.CopyleftLicenses = append(report.CopyleftLicenses, CopyleftLicense{
					File:       filepath.Join(repoName, filepath.Base(filePath)),
					Dependency: "Unknown (Heuristic)",
					License:    lic,
				})
			}
		}
	}
}
