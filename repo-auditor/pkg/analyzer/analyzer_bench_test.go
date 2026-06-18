package analyzer

import (
	"path/filepath"
	"testing"
)

func BenchmarkHasSpringBootEntrypoint(b *testing.B) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/java-project")
	a := NewAnalyzer(fixtureDir, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.hasSpringBootEntrypoint(fixtureDir)
	}
}

func BenchmarkHasQuarkusEntrypoint(b *testing.B) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/java-project")
	a := NewAnalyzer(fixtureDir, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.hasQuarkusEntrypoint(fixtureDir)
	}
}
