# Repo Auditor

Repo Auditor is a comprehensive tool suite designed to recursively scan local Git repositories, extract their software architecture, map interdependencies, and run local security scans. It generates interactive architecture maps and security reports in Markdown, utilizing Mermaid.js for diagrams.

The project is split into deux main components:
1.  **`repo-auditor` (Go CLI)**: The high-speed backend engine that performs the heavy lifting.
2.  **`repo-auditor-extension` (VS Code Extension)**: The graphical frontend providing a seamless developer experience directly inside VS Code.

---

## 1. Stack Technique de Validation (Pré-requis locaux)

Pour tirer pleinement parti de Repo Auditor et de l'ensemble de ses analyses (DevSecOps), assurez-vous d'avoir installé les outils CLI suivants dans votre `PATH` :

*   **Go** (1.21+) : Pour exécuter ou compiler le moteur principal.
*   **Node.js / npm** (18.x+) : Pour l'extension VS Code.
*   **Trivy** : Scanner de vulnérabilités et de configuration (`brew install trivy`).
*   **Hadolint** : Linter Dockerfile (`brew install hadolint`).
*   **Kube-Linter** : Analyse de conformité Helm/Kubernetes (`brew install kube-linter`).
*   **Gocyclo** : Analyse de complexité cyclomatique pour le code Go (`go install github.com/fzipp/gocyclo/cmd/gocyclo@latest`).

*Note : L'outil est tolérant aux pannes. Si l'un de ces binaires n'est pas trouvé, l'analyse correspondante sera ignorée (ou un fallback sera utilisé, comme pour la complexité AST), sans crasher l'application.*

---

## Project Structure

```text
.
├── repo-auditor/                   # The Go CLI application
│   ├── cmd/auditor/                # Entrypoint for the CLI
│   ├── pkg/analyzer/               # Core scanning logic (dependencies, Java/Go detection, AST complexity fallback)
│   ├── pkg/renderer/               # Markdown generation with Mermaid.js integration
│   ├── pkg/security/               # Security logic (Trivy, Gitleaks, Hadolint, Kube-Linter, License SCA)
│   └── go.mod                      # Go dependencies
│
└── repo-auditor-extension/         # The TypeScript VS Code Extension
    ├── src/                        # Extension source code
    │   ├── extension.ts            # Extension entrypoint
    │   └── panels/                 # ArchitectureWebview.ts
    └── package.json                # Extension manifests
```

---

## Check-list des Commandes de Test / Validation du Moteur Go

Pour valider le moteur localement (idéal pour un hook de `pre-commit`) :

1. Naviguer dans le dossier Go :
   ```bash
   cd repo-auditor
   ```
2. Mettre à jour les dépendances :
   ```bash
   go mod tidy
   ```
3. Exécuter la suite de tests unitaires (valide les parsers XML/JSON de Kube-Linter, des licences, et la simulation de complexité AST locale) :
   ```bash
   go test ./...
   ```
4. Compiler le moteur pour vérifier qu'aucune erreur de type n'existe :
   ```bash
   go build ./...
   ```

---

## Format du Rapport Généré (architecture_map.md)

Lorsque vous exécutez `repo-auditor` (via CLI ou VS Code), il génère un rapport Markdown contenant :

1. **System Topology** (`graph TD`) : Vue macro des microservices et de leurs technologies.
2. **Dependencies and Data Flow** (`graph LR`) : Graphe des interactions détectées entre projets.
3. **Rapport de Sécurité Flash** :
   * Vulnérabilités (Trivy)
   * Détection de Secrets (Gitleaks)
   * Linting Dockerfile (Hadolint)
4. **## 📊 Conformité & Production (Kube-Linter)**
   * Liste les composants Helm analysés, les règles enfreintes (spécifiquement les Liveness/Readiness probes et les limites/requêtes CPU/RAM) et propose une remédiation.
5. **## ⚖️ Conformité des Licences Open Source**
   * Liste les dépendances des fichiers `go.mod` et `pom.xml`, indique le langage, la licence détectée, et alerte sur le statut ("Sûr" ou "RISQUE CRITIQUE (Copyleft)" pour les licences bloquantes comme GPL/AGPL).
6. **## 📉 Dette Technique & Complexité**
   * Remonte les fonctions Go les plus complexes en utilisant `gocyclo` (ou l'AST Go natif en fallback). Affiche une icône d'alerte (⚠️) si le score de complexité dépasse 15, permettant de repérer rapidement la dette technique.

---

### Exécution via CLI

```bash
cd repo-auditor
go run ./cmd/auditor --path /path/to/your/projects --concurrency 8
```

### Exécution via Extension VS Code

1. `cd repo-auditor-extension && npm install && npm run compile`
2. Ouvrez le dossier dans VS Code, appuyez sur `F5`.
3. Lancez la commande **`Audit Repository`**.
