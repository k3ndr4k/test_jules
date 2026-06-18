package analyzer

import (
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
		{From: "Traefik", To: "Spring", Type: "HTTP"},
		{From: "Spring", To: "Redis", Type: "Cache"},
		{From: "Spring", To: "RabbitMQ", Type: "Queue"},
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
