package analyzer

import (
	"path/filepath"
	"testing"
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
