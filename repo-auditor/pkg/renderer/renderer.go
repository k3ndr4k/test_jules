package renderer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"repo-auditor/pkg/analyzer"
	"repo-auditor/pkg/security"
)

func GenerateMarkdown(projects []*analyzer.Project, secReport *security.SecurityReport, advGraph string, outputDir string) error {
	outPath := filepath.Join(outputDir, "architecture_map.md")

	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	file.WriteString("# Architecture & Data Flow Map\n\n")

	if advGraph != "" {
		file.WriteString("## System Topology & Data Flow\n\n")
		file.WriteString("```mermaid\n")
		file.WriteString(advGraph + "\n")
		file.WriteString("```\n\n")
	} else {
		// Section 1: Architecture Diagram
		file.WriteString("## System Topology\n\n")
		file.WriteString("```mermaid\ngraph TD\n")
		for _, p := range projects {
			techs := ""
			if len(p.Technologies) > 0 {
				techs = fmt.Sprintf(" [%s]", strings.Join(p.Technologies, ", "))
			}
			safeName := strings.ReplaceAll(p.Name, "-", "_")
			safeName = strings.ReplaceAll(safeName, ".", "_")
			file.WriteString(fmt.Sprintf("  %s(\"%s%s\")\n", safeName, p.Name, techs))
		}
		file.WriteString("```\n\n")

		// Section 2: Data Flow Diagram
		file.WriteString("## Dependencies and Data Flow\n\n")
		file.WriteString("```mermaid\ngraph LR\n")
		hasEdges := false
		for _, p := range projects {
			safeSourceName := strings.ReplaceAll(p.Name, "-", "_")
			safeSourceName = strings.ReplaceAll(safeSourceName, ".", "_")

			for _, dep := range p.Dependencies {
				safeTargetName := strings.ReplaceAll(dep, "-", "_")
				safeTargetName = strings.ReplaceAll(safeTargetName, ".", "_")
				file.WriteString(fmt.Sprintf("  %s --> %s\n", safeSourceName, safeTargetName))
				hasEdges = true
			}

			for _, link := range p.Links {
				safeFromName := strings.ReplaceAll(link.From, "-", "_")
				safeFromName = strings.ReplaceAll(safeFromName, ".", "_")
				safeToName := strings.ReplaceAll(link.To, "-", "_")
				safeToName = strings.ReplaceAll(safeToName, ".", "_")

				if link.Type != "" {
					file.WriteString(fmt.Sprintf("  %s -->|%s| %s\n", safeFromName, link.Type, safeToName))
				} else {
					file.WriteString(fmt.Sprintf("  %s --> %s\n", safeFromName, safeToName))
				}
				hasEdges = true
			}
		}
		if !hasEdges {
			file.WriteString("  %% No dependencies detected\n")
		}
		file.WriteString("```\n\n")
	}

	// Section 3: Security Report
	file.WriteString("## Rapport de Sécurité Flash\n\n")

	if secReport == nil || (secReport.CriticalCount == 0 && secReport.HighCount == 0 && secReport.MediumCount == 0 && len(secReport.GitleaksSecrets) == 0 && len(secReport.HadolintIssues) == 0 && len(secReport.KubeLinterIssues) == 0 && len(secReport.CopyleftLicenses) == 0 && len(secReport.CycloComplexities) == 0 && !secReport.HadolintSkipped && !secReport.KubeLinterSkipped && !secReport.GocycloSkipped) {
		file.WriteString("*Aucune vulnérabilité ou problème détecté, ou outils non disponibles.*\n")
		return nil
	}

	file.WriteString("### Vulnérabilités (Trivy)\n\n")
	file.WriteString("| Sévérité | Nombre |\n")
	file.WriteString("|----------|--------|\n")
	file.WriteString(fmt.Sprintf("| CRITICAL | %d |\n", secReport.CriticalCount))
	file.WriteString(fmt.Sprintf("| HIGH     | %d |\n", secReport.HighCount))
	file.WriteString(fmt.Sprintf("| MEDIUM   | %d |\n\n", secReport.MediumCount))

	if len(secReport.TopVulns) > 0 {
		file.WriteString("#### Top 5 Vulnérabilités\n\n")
		file.WriteString("| Paquet | CVE | Description |\n")
		file.WriteString("|--------|-----|-------------|\n")
		for _, v := range secReport.TopVulns {
			desc := strings.ReplaceAll(v.Description, "\n", " ")
			if len(desc) > 50 {
				desc = desc[:47] + "..."
			}
			file.WriteString(fmt.Sprintf("| %s | %s | %s |\n", v.PkgName, v.VulnerabilityID, desc))
		}
		file.WriteString("\n")
	}

	if len(secReport.SecretsAndIaC) > 0 {
		file.WriteString("#### Secrets & IaC Issues (Trivy)\n\n")
		file.WriteString("| Cible | Type | Problème |\n")
		file.WriteString("|-------|------|----------|\n")
		for _, s := range secReport.SecretsAndIaC {
			file.WriteString(fmt.Sprintf("| %s | %s | %s |\n", s.Target, s.Class, s.Title))
		}
		file.WriteString("\n")
	}

	if len(secReport.GitleaksSecrets) > 0 {
		file.WriteString("### Détection de Secrets (Gitleaks)\n\n")
		file.WriteString("| Fichier | Règle | Détail |\n")
		file.WriteString("|---------|-------|--------|\n")
		for _, s := range secReport.GitleaksSecrets {
			file.WriteString(fmt.Sprintf("| %s | %s | %s |\n", s.File, s.Rule, s.Secret))
		}
		file.WriteString("\n")
	}

	file.WriteString("### Linting Dockerfile (Hadolint)\n\n")
	if secReport.HadolintSkipped {
		file.WriteString("*Hadolint non installé - Analyse du Dockerfile ignorée*\n\n")
	} else if len(secReport.HadolintIssues) > 0 {
		file.WriteString("| Fichier | Ligne | Niveau | Règle | Message |\n")
		file.WriteString("|---------|-------|--------|-------|---------|\n")
		for _, h := range secReport.HadolintIssues {
			file.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s |\n", h.File, h.Line, h.Level, h.Code, h.Message))
		}
		file.WriteString("\n")
	} else {
		file.WriteString("*Aucun problème Dockerfile détecté.*\n\n")
	}

	file.WriteString("## 📊 Conformité & Production (Kube-Linter)\n\n")
	if secReport.KubeLinterSkipped {
		file.WriteString("*kube-linter non installé - Analyse ignorée*\n\n")
	} else if len(secReport.KubeLinterIssues) > 0 {
		file.WriteString("| Composant Helm | Règle Violée | Recommandation |\n")
		file.WriteString("|----------------|--------------|----------------|\n")
		for _, k := range secReport.KubeLinterIssues {
			file.WriteString(fmt.Sprintf("| %s | %s | %s |\n", k.File, k.Check, k.Remediation))
		}
		file.WriteString("\n")
	} else {
		file.WriteString("*Aucun problème de Probes ou de Limites détecté.*\n\n")
	}

	file.WriteString("## ⚖️ Conformité des Licences Open Source\n\n")
	if len(secReport.CopyleftLicenses) > 0 {
		file.WriteString("| Dépendance | Langage | Licence | Statut |\n")
		file.WriteString("|------------|---------|---------|--------|\n")
		for _, l := range secReport.CopyleftLicenses {
			file.WriteString(fmt.Sprintf("| %s | %s | %s | **%s** |\n", l.Dependency, l.Language, l.License, l.Status))
		}
		file.WriteString("\n")
	} else {
		file.WriteString("*Aucun problème de licence détecté.*\n\n")
	}

	file.WriteString("## 📉 Dette Technique & Complexité\n\n")
	if secReport.GocycloSkipped {
		file.WriteString("*gocyclo non installé - Analyse AST native fallback utilisée*\n\n")
	}
	if len(secReport.CycloComplexities) > 0 {
		file.WriteString("| Fichier | Fonction | Score de Complexité |\n")
		file.WriteString("|---------|----------|---------------------|\n")
		for _, c := range secReport.CycloComplexities {
			alert := ""
			if c.Score > 15 {
				alert = " ⚠️"
			}
			file.WriteString(fmt.Sprintf("| %s | %s | %d%s |\n", c.File, c.Function, c.Score, alert))
		}
		file.WriteString("\n")
	} else {
		file.WriteString("*Aucun code source complexe analysé.*\n\n")
	}

	return nil
}
