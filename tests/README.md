# Tests & Golden Files Fixtures

Ce répertoire contient les jeux de données statiques ("Golden Files") utilisés par les tests unitaires de `repo-auditor` pour valider la robustesse des parsers de sécurité et d'architecture sans dépendre de l'exécution d'outils externes ou de projets réels.

## Structure des Fixtures

Les fichiers de tests sont situés dans `/tests/fixtures/` :

*   **`java-project`** : Contient un `pom.xml` factice avec des licences critiques (ex: `GPL-3.0`) et des annotations Spring Boot simulées (`@RestController`), permettant de tester le scanner SCA heuristique et la détection d'architecture.
*   **`helm-chart`** : Simule un projet Kubernetes/Helm manquant volontairement de configuration (pas de `livenessProbe`, pas de `resources.limits`). Il contient également le résultat attendu de Kube-Linter (`kube-linter-report.json`) que le moteur Go doit parser.
*   **`go-complex`** : Fournit un fichier source Go avec un haut niveau d'imbrication logique pour valider le calcul de complexité cyclomatique via l'AST (Alternative à Go-Cyclo).
*   **`expected_architecture_map.md`** : C'est le rendu Markdown final théoriquement attendu après agrégation de toutes les analyses sur ces dossiers de fixtures. Il sert de point de repère visuel.

## Comment mettre à jour les Golden Files ?

Si vous modifiez la structure des données générées (par exemple, suite à une mise à jour de `kube-linter` changeant le format JSON), vous devez :

1.  Régénérer le fichier JSON à la main. Par exemple :
    ```bash
    cd tests/fixtures/helm-chart
    kube-linter lint --format json . > kube-linter-report.json
    ```
2.  Mettre à jour le fichier `expected_architecture_map.md` (si la syntaxe d'affichage a changé).
3.  Lancer la suite de tests pour vérifier que le parser Go dans `pkg/security` ou `pkg/analyzer` le gère toujours correctement :
    ```bash
    cd repo-auditor
    go test ./...
    ```

Cette approche assure que les tests du moteur d'audit restent reproductibles, rapides et idempotents dans n'importe quel environnement d'intégration continue (CI).
