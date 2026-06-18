package analyzer

import (
	"path/filepath"
	"testing"
)

func BenchmarkAnalyzeRepository(b *testing.B) {
	fixtureDir, _ := filepath.Abs("../../../tests/fixtures/multi-tier-app")
	a := NewAnalyzer(fixtureDir, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.analyzeRepository(fixtureDir)
	}
}
