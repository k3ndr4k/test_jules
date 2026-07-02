package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BobuSumisu/aho-corasick"
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestJavaSpringBootDetectionFromFixture(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/java-project")

	a := NewAnalyzer(fixtureDir, 1)
	p, err := a.analyzeRepository(fixtureDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if p.Name != "java-project" {
		t.Errorf("Expected project name 'java-project', got %s", p.Name)
	}

	if !contains(p.Technologies, "Java/Kotlin") {
		t.Errorf("Expected Java/Kotlin tech, got %v", p.Technologies)
	}
	// Note: The analyzer heuristic looks for "org.springframework.boot" string. The fixture has it.
	if !contains(p.Technologies, "Spring Boot") {
		t.Errorf("Expected Spring Boot tech, got %v", p.Technologies)
	}
}

func TestHelmDetectionFromFixture(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/helm-chart")

	a := NewAnalyzer(fixtureDir, 1)
	p, err := a.analyzeRepository(fixtureDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !contains(p.Technologies, "Helm") {
		t.Errorf("Expected Helm tech, got %v", p.Technologies)
	}
}

func TestGoComplexDetectionFromFixture(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/go-complex")

	a := NewAnalyzer(fixtureDir, 1)
	p, err := a.analyzeRepository(fixtureDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if p.Name != "go-complex" {
		t.Errorf("Expected project name 'go-complex', got %s", p.Name)
	}
}

func TestMultiTierAppFlowExtraction(t *testing.T) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/multi-tier-app")

	a := NewAnalyzer(fixtureDir, 1)
	p, err := a.analyzeRepository(fixtureDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	expectedLinks := []DependencyLink{
		{From: "Traefik", To: "Nginx", Type: "HTTP"},
		{From: "Traefik", To: "Angular", Type: "HTTP"},
		{From: "Traefik", To: "Spring", Type: "HTTP"},
		{From: "Traefik", To: "Quarkus", Type: "HTTP"},
		{From: "Traefik", To: "Flask", Type: "HTTP"},
		{From: "Traefik", To: "DotNet", Type: "HTTP"},
		{From: "Spring", To: "Redis", Type: "Cache"},
		{From: "Spring", To: "RabbitMQ", Type: "Queue"},
		{From: "Quarkus", To: "Postgres", Type: "JDBC"},
		{From: "Migrator", To: "Postgres", Type: "Init Script"},
	}

	for _, expected := range expectedLinks {
		found := false
		for _, actual := range p.Links {
			if actual.From == expected.From && actual.To == expected.To && actual.Type == expected.Type {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected link not found: %+v", expected)
		}
	}
}

func BenchmarkFindDependenciesInRepo(b *testing.B) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/multi-tier-app")
	a := NewAnalyzer(fixtureDir, 1)

	projectNames := make(map[string]bool)
	var allNames []string
	projectNames["Nginx"] = true
	projectNames["Spring"] = true
	projectNames["Redis"] = true
	projectNames["RabbitMQ"] = true
	projectNames["Traefik"] = true
	allNames = append(allNames, "Nginx", "Spring", "Redis", "RabbitMQ", "Traefik")

	// Add dummy project names to increase the map size and emphasize the performance problem
	for i := 0; i < 100; i++ {
		name := filepath.Join("DummyProject", string(rune(i)))
		projectNames[name] = true
		allNames = append(allNames, name)
	}

	trie := ahocorasick.NewTrieBuilder().AddStrings(allNames).Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.findDependenciesInRepo(fixtureDir, projectNames, "Traefik", trie)
	}
}

func TestMapDependencies(t *testing.T) {
	tempDir := t.TempDir()

	projADir := filepath.Join(tempDir, "ProjA")
	projBDir := filepath.Join(tempDir, "ProjB")
	projCDir := filepath.Join(tempDir, "ProjC")

	os.MkdirAll(projADir, 0755)
	os.MkdirAll(projBDir, 0755)
	os.MkdirAll(projCDir, 0755)

	// ProjA depends on ProjB
	os.WriteFile(filepath.Join(projADir, "main.go"), []byte("import \"ProjB\""), 0644)

	// ProjA has node_modules containing ProjC (should be skipped)
	nodeModulesDir := filepath.Join(projADir, "node_modules")
	os.MkdirAll(nodeModulesDir, 0755)
	os.WriteFile(filepath.Join(nodeModulesDir, "index.js"), []byte("const c = require('ProjC')"), 0644)

	// ProjB depends on ProjC
	os.WriteFile(filepath.Join(projBDir, "package.json"), []byte("{\"dependencies\": {\"ProjC\": \"1.0.0\"}}"), 0644)

	// ProjC depends on ProjA and ProjB
	os.WriteFile(filepath.Join(projCDir, "config.yaml"), []byte("services:\n  - ProjA\n  - ProjB"), 0644)

	projects := []*Project{
		{Name: "ProjA", Path: projADir},
		{Name: "ProjB", Path: projBDir},
		{Name: "ProjC", Path: projCDir},
	}

	a := NewAnalyzer(tempDir, 1)
	a.mapDependencies(projects)

	// Verify ProjA
	if !contains(projects[0].Dependencies, "ProjB") {
		t.Errorf("Expected ProjA to depend on ProjB, but got %v", projects[0].Dependencies)
	}
	if contains(projects[0].Dependencies, "ProjC") {
		t.Errorf("Expected ProjA to NOT depend on ProjC (should be skipped), but got %v", projects[0].Dependencies)
	}
	if contains(projects[0].Dependencies, "ProjA") {
		t.Errorf("Expected ProjA to NOT depend on itself, but got %v", projects[0].Dependencies)
	}

	// Verify ProjB
	if !contains(projects[1].Dependencies, "ProjC") {
		t.Errorf("Expected ProjB to depend on ProjC, but got %v", projects[1].Dependencies)
	}

	// Verify ProjC
	if !contains(projects[2].Dependencies, "ProjA") {
		t.Errorf("Expected ProjC to depend on ProjA, but got %v", projects[2].Dependencies)
	}
	if !contains(projects[2].Dependencies, "ProjB") {
		t.Errorf("Expected ProjC to depend on ProjB, but got %v", projects[2].Dependencies)
	}
}

func TestMapDependencies_Empty(t *testing.T) {
	a := NewAnalyzer(t.TempDir(), 1)

	// This should not panic
	a.mapDependencies([]*Project{})
	a.mapDependencies(nil)
}
