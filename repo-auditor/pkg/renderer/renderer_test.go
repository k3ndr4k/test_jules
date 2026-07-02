package renderer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"repo-auditor/pkg/analyzer"
	"repo-auditor/pkg/security"
)

func TestExpectedArchitectureMapMatches(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "renderer_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	projects := []*analyzer.Project{
		{
			Name:         "go-complex",
			Path:         "go-complex",
			Technologies: []string{"Go"},
		},
		{
			Name:         "helm-chart",
			Path:         "helm-chart",
			Technologies: []string{"Helm"},
		},
		{
			Name:         "java-project",
			Path:         "java-project",
			Technologies: []string{"Java/Kotlin", "Spring Boot", "HTTP Entrypoint (Spring)"},
		},
	}

	secReport := &security.SecurityReport{
		KubeLinterIssues: []security.KubeLinterFinding{
			{File: "helm-chart/deployment.yaml", Check: "no-liveness-probe", Message: "container \"test-container\" does not have a livenessProbe", Remediation: "Specify a livenessProbe."},
			{File: "helm-chart/deployment.yaml", Check: "no-readiness-probe", Message: "container \"test-container\" does not have a readinessProbe", Remediation: "Specify a readinessProbe."},
			{File: "helm-chart/deployment.yaml", Check: "unset-cpu-requirements", Message: "container \"test-container\" has no cpu limit", Remediation: "Set cpu limits and requests."},
			{File: "helm-chart/deployment.yaml", Check: "unset-memory-requirements", Message: "container \"test-container\" has no memory limit", Remediation: "Set memory limits and requests."},
		},
		CopyleftLicenses: []security.CopyleftLicense{
			{Language: "Java", Dependency: "Root Pom License", License: "GPL-3.0", Status: "RISQUE CRITIQUE (Copyleft)"},
		},
		CycloComplexities: []security.CycloFinding{
			{File: "go-complex/main.go", Function: "UltraComplexFunction", Score: 26},
			{File: "go-complex/main.go", Function: "main", Score: 1},
		},
		GocycloSkipped: true,
	}

	err = GenerateMarkdown(projects, secReport, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	generatedPath := filepath.Join(tempDir, "architecture_map.md")
	generatedData, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatalf("Failed to read generated markdown: %v", err)
	}

	expectedPath, _ := filepath.Abs("../../../tests/fixtures/expected_architecture_map.md")
	expectedData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("Failed to read expected markdown: %v", err)
	}

	genStr := strings.TrimSpace(string(generatedData))
	expStr := strings.TrimSpace(string(expectedData))

	if genStr != expStr {
		os.WriteFile("generated.md", []byte(genStr), 0644)
		t.Errorf("Generated markdown does not match expected Golden File. Length diff: gen=%d, exp=%d. Wrote generated.md for inspection.", len(genStr), len(expStr))
	}
}

func TestMultiTierAdvancedArchitecture(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/multi-tier-app")

	a := analyzer.NewAnalyzer(fixtureDir, 1)

	// We only care about the advanced graph for this test, not the full project list
	_, _, advGraph, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	expectedGraph := `graph TD
    Client([🌐 Internet]) -->|HTTP/HTTPS| Traefik[💧 Ingress: Traefik]

    Traefik -->|Proxy: /| Nginx[🎨 Frontend: Nginx/HTML]
    Traefik -->|Proxy: /app| Angular[🅰️ Frontend: Angular]

    Traefik -->|Proxy: /api/spring| Spring[☕ API: Spring Boot]
    Traefik -->|Proxy: /api/quarkus| Quarkus[⚛️ API: Quarkus]
    Traefik -->|Proxy: /api/flask| Flask[🐍 API: Python/Flask]
    Traefik -->|Proxy: /api/dotnet| DotNet[🟣 API: .NET]

    Spring -->|Cache| Redis[(🛑 Cache: Redis)]
    Spring -->|Async| Rabbit[🐇 Queue: RabbitMQ]

    Quarkus -->|JDBC| Postgres[(🐘 BDD: PostgreSQL 13.2)]
    Migrator[📜 DB Migrator] -->|Init Script| Postgres`

	if advGraph != expectedGraph {
		t.Errorf("Extracted advanced graph did not match expectation.\nExpected:\n%s\nGot:\n%s", expectedGraph, advGraph)
	}
}

func TestGenerateMarkdown_FileError(t *testing.T) {
	err := GenerateMarkdown(nil, nil, "", "/invalid/dir/that/does/not/exist")
	if err == nil {
		t.Errorf("Expected error for invalid output directory, got nil")
	}
}

func TestGenerateMarkdown_AdvancedGraph(t *testing.T) {
	tempDir := t.TempDir()

	advGraph := "graph TD\n  A --> B"
	err := GenerateMarkdown(nil, nil, advGraph, tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	generatedPath := filepath.Join(tempDir, "architecture_map.md")
	data, _ := os.ReadFile(generatedPath)
	strData := string(data)

	if !strings.Contains(strData, "## System Topology & Data Flow") {
		t.Errorf("Missing advanced graph section header")
	}
	if !strings.Contains(strData, advGraph) {
		t.Errorf("Missing advanced graph content")
	}
}

func TestGenerateMarkdown_DependenciesAndLinks(t *testing.T) {
	tempDir := t.TempDir()

	projects := []*analyzer.Project{
		{
			Name: "Proj1",
			Dependencies: []string{"Dep-A"},
			Links: []analyzer.DependencyLink{
				{From: "Proj1", To: "LinkA", Type: "HTTP"},
				{From: "Proj1", To: "LinkB", Type: ""}, // Empty type
			},
		},
	}

	err := GenerateMarkdown(projects, nil, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	generatedPath := filepath.Join(tempDir, "architecture_map.md")
	data, _ := os.ReadFile(generatedPath)
	strData := string(data)

	if !strings.Contains(strData, "Proj1 --> Dep_A") {
		t.Errorf("Missing dependency output")
	}
	if !strings.Contains(strData, "Proj1 -->|HTTP| LinkA") {
		t.Errorf("Missing typed link output")
	}
	if !strings.Contains(strData, "Proj1 --> LinkB") {
		t.Errorf("Missing untyped link output")
	}
}

func TestGenerateMarkdown_EmptySecReport(t *testing.T) {
	tempDir := t.TempDir()

	// nil sec report
	err := GenerateMarkdown(nil, nil, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(tempDir, "architecture_map.md"))
	if !strings.Contains(string(data), "*Aucune vulnérabilité ou problème détecté, ou outils non disponibles.*") {
		t.Errorf("Expected empty sec report message for nil report")
	}

	// empty sec report
	emptyReport := &security.SecurityReport{}
	err = GenerateMarkdown(nil, emptyReport, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}
	data, _ = os.ReadFile(filepath.Join(tempDir, "architecture_map.md"))
	if !strings.Contains(string(data), "*Aucune vulnérabilité ou problème détecté, ou outils non disponibles.*") {
		t.Errorf("Expected empty sec report message for empty report")
	}
}

func TestGenerateMarkdown_FullSecReport(t *testing.T) {
	tempDir := t.TempDir()

	secReport := &security.SecurityReport{
		CriticalCount: 1,
		HighCount:     2,
		MediumCount:   3,
		TopVulns: []security.Vulnerability{
			{PkgName: "pkg1", VulnerabilityID: "CVE-1", Description: "Short desc"},
			{PkgName: "pkg2", VulnerabilityID: "CVE-2", Description: "This is a very long description that exceeds fifty characters to test truncation"},
		},
		SecretsAndIaC: []security.SecretOrIaC{
			{Target: "file1", Class: "secret", Title: "Secret found"},
		},
		GitleaksSecrets: []security.GitleaksFinding{
			{File: "file2", Rule: "rule1", Secret: "supersecret"},
		},
		HadolintIssues: []security.HadolintFinding{
			{File: "Dockerfile", Line: 1, Level: "error", Code: "DL3000", Message: "Use absolute WORKDIR"},
		},
		KubeLinterIssues: []security.KubeLinterFinding{
			{File: "helm-chart/deployment.yaml", Check: "no-liveness-probe", Remediation: "Specify a livenessProbe."},
		},
		CopyleftLicenses: []security.CopyleftLicense{
			{Language: "Java", Dependency: "Root Pom License", License: "GPL-3.0", Status: "RISQUE CRITIQUE (Copyleft)"},
		},
		CycloComplexities: []security.CycloFinding{
			{File: "go-complex/main.go", Function: "UltraComplexFunction", Score: 26},
		},
	}

	err := GenerateMarkdown(nil, secReport, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(tempDir, "architecture_map.md"))
	strData := string(data)

	if !strings.Contains(strData, "| CRITICAL | 1 |") {
		t.Errorf("Missing critical count")
	}
	if !strings.Contains(strData, "Short desc") {
		t.Errorf("Missing short description")
	}
	if !strings.Contains(strData, "This is a very long description that exceeds fi...") {
		t.Errorf("Truncated description not found or incorrect")
	}
	if !strings.Contains(strData, "file1 | secret | Secret found") {
		t.Errorf("Missing SecretsAndIaC")
	}
	if !strings.Contains(strData, "file2 | rule1 | supersecret") {
		t.Errorf("Missing GitleaksSecrets")
	}
	if !strings.Contains(strData, "Dockerfile | 1 | error | DL3000 | Use absolute WORKDIR") {
		t.Errorf("Missing HadolintIssues")
	}
	if !strings.Contains(strData, "helm-chart/deployment.yaml | no-liveness-probe | Specify a livenessProbe.") {
		t.Errorf("Missing KubeLinterIssues")
	}
	if !strings.Contains(strData, "Root Pom License | Java | GPL-3.0 | **RISQUE CRITIQUE (Copyleft)**") {
		t.Errorf("Missing CopyleftLicenses")
	}
	if !strings.Contains(strData, "go-complex/main.go | UltraComplexFunction | 26 ⚠️") {
		t.Errorf("Missing CycloComplexities")
	}
}

func TestGenerateMarkdown_SkippedAndEmptyStates(t *testing.T) {
	tempDir := t.TempDir()

	secReport := &security.SecurityReport{
		HadolintSkipped:   true,
		KubeLinterSkipped: true,
		GocycloSkipped:    true,
		// Explicitly ensure there are counts so it doesn't return early
		CriticalCount: 1,
	}

	err := GenerateMarkdown(nil, secReport, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(tempDir, "architecture_map.md"))
	strData := string(data)

	if !strings.Contains(strData, "*Hadolint non installé") {
		t.Errorf("Missing Hadolint skipped message")
	}
	if !strings.Contains(strData, "*kube-linter non installé") {
		t.Errorf("Missing KubeLinter skipped message")
	}
	if !strings.Contains(strData, "*gocyclo non installé") {
		t.Errorf("Missing gocyclo skipped message")
	}

	// Test empty states for tools when NOT skipped and NO issues
	secReportEmpty := &security.SecurityReport{
		HadolintSkipped:   false,
		KubeLinterSkipped: false,
		GocycloSkipped:    false,
		CriticalCount: 1, // Prevent early return
	}

	err = GenerateMarkdown(nil, secReportEmpty, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	dataEmpty, _ := os.ReadFile(filepath.Join(tempDir, "architecture_map.md"))
	strDataEmpty := string(dataEmpty)

	if !strings.Contains(strDataEmpty, "*Aucun problème Dockerfile détecté.*") {
		t.Errorf("Missing Hadolint empty message")
	}
	if !strings.Contains(strDataEmpty, "*Aucun problème de Probes ou de Limites détecté.*") {
		t.Errorf("Missing KubeLinter empty message")
	}
	if !strings.Contains(strDataEmpty, "*Aucun problème de licence détecté.*") {
		t.Errorf("Missing License empty message")
	}
	if !strings.Contains(strDataEmpty, "*Aucun code source complexe analysé.*") {
		t.Errorf("Missing Gocyclo empty message")
	}
}

func TestGenerateMarkdown_NoDependenciesOrLinks(t *testing.T) {
	tempDir := t.TempDir()

	projects := []*analyzer.Project{
		{
			Name:         "IsolatedProject",
			Path:         "isolated",
			Technologies: []string{"Go"},
			Dependencies: nil,
			Links:        nil,
		},
	}

	err := GenerateMarkdown(projects, nil, "", tempDir)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	generatedPath := filepath.Join(tempDir, "architecture_map.md")
	data, _ := os.ReadFile(generatedPath)
	strData := string(data)

	if !strings.Contains(strData, "%% No dependencies detected") {
		t.Errorf("Missing 'No dependencies detected' comment for isolated project")
	}
}
