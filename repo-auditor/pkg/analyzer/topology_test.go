package analyzer

import (
	"os"
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

func TestExtractAdvancedArchitecture_PartialMatch(t *testing.T) {
	dir := t.TempDir()

	// Create some but not all files
	files := map[string]string{
		"routes.yaml":        "frontend-nginx-service",
		"Dockerfile":         "FROM nginx:latest",
		"package.json":       `{"name": "angular"}`,
		"pom.xml":            "<dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><artifactId>quarkus</artifactId></dependency></dependencies>",
		"app.py":             "import flask",
		"application.yml":    "redis: host\nrabbitmq: host",
		"docker-compose.yml": "image: postgres",
		"project.csproj":     "<Project></Project>",
	}

	for name, content := range files {
		err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to write file %s: %v", name, err)
		}
	}

	// Intentionally missing init.sql / migrate.sql to make hasMigrator = false

	result := ExtractAdvancedArchitecture(dir)
	if result != "" {
		t.Errorf("Expected empty string for partial match, got: %v", result)
	}
}

func TestExtractAdvancedArchitecture_IgnoredDirectory(t *testing.T) {
	dir := t.TempDir()

	ignoredDir := filepath.Join(dir, "node_modules")
	err := os.Mkdir(ignoredDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create ignored dir: %v", err)
	}

	// Create all files inside the ignored directory
	files := map[string]string{
		"routes.yaml":        "frontend-nginx-service",
		"Dockerfile":         "FROM nginx:latest",
		"package.json":       `{"name": "angular"}`,
		"pom.xml":            "<dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><artifactId>quarkus</artifactId></dependency></dependencies>",
		"app.py":             "import flask",
		"application.yml":    "redis: host\nrabbitmq: host",
		"docker-compose.yml": "image: postgres",
		"init.sql":           "CREATE TABLE foo;",
		"project.csproj":     "<Project></Project>",
	}

	for name, content := range files {
		err := os.WriteFile(filepath.Join(ignoredDir, name), []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to write file %s: %v", name, err)
		}
	}

	result := ExtractAdvancedArchitecture(dir)
	if result != "" {
		t.Errorf("Expected empty string because files are in ignored directory, got: %v", result)
	}
}
