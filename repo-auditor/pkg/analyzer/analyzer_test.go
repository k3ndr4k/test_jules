package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/go-git/go-git/v5"
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestAnalyzeRepository(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "analyzer_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	files := []string{
		"go.mod",
		"package.json",
		"Dockerfile",
	}

	for _, f := range files {
		fpath := filepath.Join(tempDir, f)
		if err := os.WriteFile(fpath, []byte("dummy content"), 0644); err != nil {
			t.Fatalf("Failed to create dummy file: %v", err)
		}
	}

	a := NewAnalyzer(tempDir, 1)
	p, err := a.analyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if p.Name != filepath.Base(tempDir) {
		t.Errorf("Expected project name %s, got %s", filepath.Base(tempDir), p.Name)
	}

	expectedTechs := []string{"Go", "Node.js", "Docker"}

	sort.Strings(expectedTechs)
	sort.Strings(p.Technologies)

	if len(p.Technologies) != len(expectedTechs) {
		t.Errorf("Expected %d technologies, got %d", len(expectedTechs), len(p.Technologies))
	}

	for i, tech := range expectedTechs {
		if p.Technologies[i] != tech {
			t.Errorf("Expected technology %s, got %s", tech, p.Technologies[i])
		}
	}
}

func TestSpringBootDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sb_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.WriteFile(filepath.Join(tempDir, "pom.xml"), []byte(`
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
	`), 0644)
	os.WriteFile(filepath.Join(tempDir, "Controller.java"), []byte(`
		import org.springframework.web.bind.annotation.RestController;
		@RestController
		public class MyController {}
	`), 0644)

	a := NewAnalyzer(tempDir, 1)
	p, err := a.analyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !contains(p.Technologies, "Java/Kotlin") {
		t.Errorf("Expected Java/Kotlin tech, got %v", p.Technologies)
	}
	if !contains(p.Technologies, "Spring Boot") {
		t.Errorf("Expected Spring Boot tech, got %v", p.Technologies)
	}
	if !contains(p.Technologies, "HTTP Entrypoint (Spring)") {
		t.Errorf("Expected HTTP Entrypoint (Spring), got %v", p.Technologies)
	}
}

func TestQuarkusDetection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "quarkus_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	os.WriteFile(filepath.Join(tempDir, "build.gradle"), []byte(`
		dependencies {
			implementation 'io.quarkus:quarkus-resteasy'
		}
	`), 0644)
	os.WriteFile(filepath.Join(tempDir, "Resource.java"), []byte(`
		import javax.ws.rs.Path;
		import javax.ws.rs.GET;
		@Path("/hello")
		public class MyResource {
			@GET
			public String hello() { return "hello"; }
		}
	`), 0644)

	a := NewAnalyzer(tempDir, 1)
	p, err := a.analyzeRepository(tempDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !contains(p.Technologies, "Java/Kotlin") {
		t.Errorf("Expected Java/Kotlin tech, got %v", p.Technologies)
	}
	if !contains(p.Technologies, "Quarkus") {
		t.Errorf("Expected Quarkus tech, got %v", p.Technologies)
	}
	if !contains(p.Technologies, "HTTP Entrypoint (Quarkus)") {
		t.Errorf("Expected HTTP Entrypoint (Quarkus), got %v", p.Technologies)
	}
}

func TestFindDependencies(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dep_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	projA := filepath.Join(tempDir, "projA")
	projB := filepath.Join(tempDir, "projB")

	os.Mkdir(projA, 0755)
	os.Mkdir(projB, 0755)

	os.WriteFile(filepath.Join(projA, "main.go"), []byte(`
package main
import "fmt"
func main() {
	// Call api of projB
	fmt.Println("http://projB:8080/api")
}
`), 0644)

	a := NewAnalyzer(tempDir, 1)

	projectNames := map[string]bool{
		"projA": true,
		"projB": true,
	}

	deps := a.findDependenciesInRepo(projA, projectNames, "projA")

	if len(deps) != 1 || deps[0] != "projB" {
		t.Errorf("Expected dependency 'projB', got %v", deps)
	}
}

func TestAnalyzeEndToEnd(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "e2e_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	proj1 := filepath.Join(tempDir, "service1")
	proj2 := filepath.Join(tempDir, "service2")
	os.Mkdir(proj1, 0755)
	os.Mkdir(proj2, 0755)

	_, err = git.PlainInit(proj1, false)
	if err != nil {
		t.Fatalf("Failed to init git: %v", err)
	}
	_, err = git.PlainInit(proj2, false)
	if err != nil {
		t.Fatalf("Failed to init git: %v", err)
	}

	os.WriteFile(filepath.Join(proj1, "go.mod"), []byte("module service1"), 0644)
	os.WriteFile(filepath.Join(proj2, "package.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(proj1, "config.yaml"), []byte("url: http://service2/api"), 0644)

	a := NewAnalyzer(tempDir, 2)
	projects, secReport, err := a.Analyze()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if secReport == nil {
		t.Fatalf("Expected secReport to not be nil")
	}

	if len(projects) != 2 {
		t.Fatalf("Expected 2 projects, got %d", len(projects))
	}

	var p1, p2 *Project
	for _, p := range projects {
		if p.Name == "service1" {
			p1 = p
		} else if p.Name == "service2" {
			p2 = p
		}
	}

	if p1 == nil || p2 == nil {
		t.Fatalf("Did not find both service1 and service2")
	}

	if len(p1.Dependencies) != 1 || p1.Dependencies[0] != "service2" {
		t.Errorf("service1 dependencies incorrect: %v", p1.Dependencies)
	}
}
