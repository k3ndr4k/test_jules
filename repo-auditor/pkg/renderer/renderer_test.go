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
