package security

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type SecurityReport struct {
	CriticalCount   int
	HighCount       int
	MediumCount     int
	TopVulns        []Vulnerability
	SecretsAndIaC   []SecretOrIaC
	HadolintSkipped bool
	GitleaksSecrets []GitleaksFinding
	HadolintIssues  []HadolintFinding
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
