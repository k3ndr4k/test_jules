package renderer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"repo-auditor/pkg/analyzer"
	"repo-auditor/pkg/security"
)

func GenerateMarkdown(projects []*analyzer.Project, secReport *security.SecurityReport, outputDir string) error {
	outPath := filepath.Join(outputDir, "architecture_map.md")

	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	file.WriteString("# Architecture & Data Flow Map\n\n")

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
	}
	if !hasEdges {
		file.WriteString("  %% No dependencies detected\n")
	}
	file.WriteString("```\n\n")

	// Section 3: Security Report
	file.WriteString("## Rapport de Sécurité Flash\n\n")

	if secReport == nil || (secReport.CriticalCount == 0 && secReport.HighCount == 0 && secReport.MediumCount == 0 && len(secReport.GitleaksSecrets) == 0 && len(secReport.HadolintIssues) == 0 && len(secReport.KubeLinterIssues) == 0 && len(secReport.CopyleftLicenses) == 0 && !secReport.HadolintSkipped && !secReport.KubeLinterSkipped) {
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

	file.WriteString("### Linting Helm (Kube-Linter)\n\n")
	if secReport.KubeLinterSkipped {
		file.WriteString("*kube-linter non installé - Analyse Helm ignorée*\n\n")
	} else if len(secReport.KubeLinterIssues) > 0 {
		file.WriteString("| Fichier | Check (Probes/Limits) | Message |\n")
		file.WriteString("|---------|-----------------------|---------|\n")
		for _, k := range secReport.KubeLinterIssues {
			file.WriteString(fmt.Sprintf("| %s | %s | %s |\n", k.File, k.Check, k.Message))
		}
		file.WriteString("\n")
	} else {
		file.WriteString("*Aucun problème de Probes ou de Limites détecté.*\n\n")
	}

	if len(secReport.CopyleftLicenses) > 0 {
		file.WriteString("### Alertes de Licences (SCA)\n\n")
		file.WriteString("| Fichier (go.mod/pom.xml) | Dépendance | Licence Détectée |\n")
		file.WriteString("|--------------------------|------------|------------------|\n")
		for _, l := range secReport.CopyleftLicenses {
			file.WriteString(fmt.Sprintf("| %s | %s | **%s** |\n", l.File, l.Dependency, l.License))
		}
		file.WriteString("\n")
	}

	return nil
}
