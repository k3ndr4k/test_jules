package analyzer

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractAdvancedArchitecture_Found(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../../tests/fixtures/multi-tier-app")
	if err != nil {
		t.Fatalf("Failed to get abs path: %v", err)
	}

	result := ExtractAdvancedArchitecture(fixtureDir)
	if result == "" {
		t.Errorf("Expected a graph, got empty string")
	}

	if !strings.Contains(result, "graph TD") {
		t.Errorf("Expected graph TD, got: %v", result)
	}

	// verify parts of the graph
	expectedContains := []string{
		"Traefik[💧 Ingress: Traefik]",
		"Nginx[🎨 Frontend: Nginx/HTML]",
		"Angular[🅰️ Frontend: Angular]",
		"Spring[☕ API: Spring Boot]",
		"Quarkus[⚛️ API: Quarkus]",
		"Flask[🐍 API: Python/Flask]",
		"DotNet[🟣 API: .NET]",
		"Redis[(🛑 Cache: Redis)]",
		"Rabbit[🐇 Queue: RabbitMQ]",
		"Postgres[(🐘 BDD: PostgreSQL 13.2)]",
		"Migrator[📜 DB Migrator]",
	}

	for _, expected := range expectedContains {
		if !strings.Contains(result, expected) {
			t.Errorf("Expected graph to contain %q, but it did not", expected)
		}
	}
}

func TestExtractAdvancedArchitecture_NotFound(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../../tests/fixtures/go-complex")
	if err != nil {
		t.Fatalf("Failed to get abs path: %v", err)
	}

	result := ExtractAdvancedArchitecture(fixtureDir)
	if result != "" {
		t.Errorf("Expected empty string, got: %v", result)
	}
}

func TestExtractAdvancedArchitecture_ErrorPath(t *testing.T) {
	fixtureDir := "/path/does/not/exist/surely"

	result := ExtractAdvancedArchitecture(fixtureDir)
	if result != "" {
		t.Errorf("Expected empty string on error path, got: %v", result)
	}
}
