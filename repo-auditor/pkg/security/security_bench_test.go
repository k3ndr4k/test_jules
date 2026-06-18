package security

import (
	"testing"
	"path/filepath"
)

func BenchmarkParsePomLicenses(b *testing.B) {
	fixturePath, _ := filepath.Abs("../../../tests/fixtures/java-project/pom.xml")
	report := &SecurityReport{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.CopyleftLicenses = nil
		parsePomLicenses(fixturePath, report)
	}
}
