package renderer

import (
	"repo-auditor/pkg/analyzer"
	"repo-auditor/pkg/security"
	"testing"
)

func BenchmarkGenerateMarkdown(b *testing.B) {
	tempDir := b.TempDir()

	projects := []*analyzer.Project{}
	for i := 0; i < 100; i++ {
		p := &analyzer.Project{
			Name: "my-project-name-with-dashes.and.dots",
			Dependencies: []string{
				"dep-1.2.3",
				"another.dependency-4.5",
				"third-dependency.with.dots",
			},
			Links: []analyzer.DependencyLink{
				{From: "my-project-name-with-dashes.and.dots", To: "dep-1.2.3", Type: "HTTP"},
				{From: "my-project-name-with-dashes.and.dots", To: "another.dependency-4.5", Type: "TCP"},
				{From: "my-project-name-with-dashes.and.dots", To: "third-dependency.with.dots", Type: ""},
			},
		}
		projects = append(projects, p)
	}

	secReport := &security.SecurityReport{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := GenerateMarkdown(projects, secReport, "", tempDir)
		if err != nil {
			b.Fatalf("GenerateMarkdown failed: %v", err)
		}
	}
}
