package security

import (
	"fmt"
	"testing"
)

func BenchmarkParseTrivyReport(b *testing.B) {
	// We have to build TrivyOutput according to its inline struct definition
	var trivyOut TrivyOutput
	trivyOut.Results = make([]struct {
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
	}, 100)

	for i := 0; i < 100; i++ {
		trivyOut.Results[i].Target = fmt.Sprintf("target-%d", i)

		vulns := make([]struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
			Severity        string `json:"Severity"`
			Title           string `json:"Title"`
			Description     string `json:"Description"`
		}, 50)
		for j := 0; j < 50; j++ {
			vid := fmt.Sprintf("CVE-202X-%d", j%10)
			severity := "MEDIUM"
			if j%10 == 0 {
				severity = "CRITICAL"
			} else if j%10 == 1 {
				severity = "HIGH"
			}
			vulns[j].VulnerabilityID = vid
			vulns[j].PkgName = fmt.Sprintf("pkg-%d", j)
			vulns[j].Severity = severity
			vulns[j].Title = "Test Title"
			vulns[j].Description = "Test Description"
		}
		trivyOut.Results[i].Vulnerabilities = vulns
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep := &SecurityReport{}
		parseTrivyReport(&trivyOut, rep)
	}
}
