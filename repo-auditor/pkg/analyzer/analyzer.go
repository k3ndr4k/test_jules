package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"repo-auditor/pkg/security"

	"github.com/BobuSumisu/aho-corasick"
	"github.com/go-git/go-git/v5"
)

type DependencyLink struct {
	From string
	To   string
	Type string
}

type Project struct {
	Name         string
	Path         string
	Technologies []string
	Dependencies []string
	Links        []DependencyLink
}

type Analyzer struct {
	RootPath    string
	Concurrency int
}

func NewAnalyzer(rootPath string, concurrency int) *Analyzer {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &Analyzer{
		RootPath:    rootPath,
		Concurrency: concurrency,
	}
}

func (a *Analyzer) Analyze() ([]*Project, *security.SecurityReport, string, error) {
	paths, err := a.findRepositories(a.RootPath)
	if err != nil {
		return nil, nil, "", err
	}

	secReport := &security.SecurityReport{}
	security.RunTrivyScan(a.RootPath, secReport)

	projects := a.analyzeConcurrent(paths, secReport)
	a.mapDependencies(projects)

	advGraph := ExtractAdvancedArchitecture(a.RootPath)

	return projects, secReport, advGraph, nil
}

func (a *Analyzer) findRepositories(root string) ([]string, error) {
	var repos []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			dir := filepath.Dir(path)
			_, err := git.PlainOpen(dir)
			if err == nil {
				repos = append(repos, dir)
			}
			return filepath.SkipDir
		}
		return nil
	})
	return repos, err
}

func (a *Analyzer) analyzeConcurrent(paths []string, secReport *security.SecurityReport) []*Project {
	var wg sync.WaitGroup
	pathsCh := make(chan string, len(paths))
	resultsCh := make(chan *Project, len(paths))

	var mu sync.Mutex

	for i := 0; i < a.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathsCh {
				p, err := a.analyzeRepository(path)
				if err == nil {
					resultsCh <- p

					localReport := runSecurityScansForRepo(path, p.Name)
					mergeSecurityReports(secReport, &localReport, &mu)
				}
			}
		}()
	}

	for _, p := range paths {
		pathsCh <- p
	}
	close(pathsCh)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var projects []*Project
	for p := range resultsCh {
		projects = append(projects, p)
	}

	return projects
}

func runSecurityScansForRepo(path string, projectName string) security.SecurityReport {
	var localReport security.SecurityReport
	var scanWg sync.WaitGroup

	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		security.RunGitleaksScan(path, &localReport)
	}()

	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		dockerfilePath := filepath.Join(path, "Dockerfile")
		if _, err := os.Stat(dockerfilePath); err == nil {
			security.RunHadolintScan(dockerfilePath, projectName, &localReport)
		}
	}()

	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		chartPath := filepath.Join(path, "Chart.yaml")
		templatesPath := filepath.Join(path, "templates")
		_, errChart := os.Stat(chartPath)
		_, errTemplates := os.Stat(templatesPath)
		if errChart == nil || errTemplates == nil {
			security.RunKubeLinterScan(path, projectName, &localReport)
		}
	}()

	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		goModPath := filepath.Join(path, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			security.RunLicenseScan(goModPath, path, false, &localReport)
		}
		pomPath := filepath.Join(path, "pom.xml")
		if _, err := os.Stat(pomPath); err == nil {
			security.RunLicenseScan(pomPath, projectName, true, &localReport)
		}
	}()

	scanWg.Add(1)
	go func() {
		defer scanWg.Done()
		goModPath := filepath.Join(path, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			security.RunGocycloScan(path, projectName, &localReport)
		}
	}()

	scanWg.Wait()
	return localReport
}

func mergeSecurityReports(dest *security.SecurityReport, src *security.SecurityReport, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()
	dest.GitleaksSecrets = append(dest.GitleaksSecrets, src.GitleaksSecrets...)
	dest.HadolintIssues = append(dest.HadolintIssues, src.HadolintIssues...)
	dest.KubeLinterIssues = append(dest.KubeLinterIssues, src.KubeLinterIssues...)
	dest.CopyleftLicenses = append(dest.CopyleftLicenses, src.CopyleftLicenses...)
	dest.CycloComplexities = append(dest.CycloComplexities, src.CycloComplexities...)

	if src.HadolintSkipped {
		dest.HadolintSkipped = true
	}
	if src.KubeLinterSkipped {
		dest.KubeLinterSkipped = true
	}
	if src.GocycloSkipped {
		dest.GocycloSkipped = true
	}
}

func detectRootTech(name string, techs map[string]bool, hasJavaBuild *bool) {
	if name == "go.mod" {
		techs["Go"] = true
	} else if name == "package.json" {
		techs["Node.js"] = true
	} else if name == "requirements.txt" {
		techs["Python"] = true
	} else if name == "Dockerfile" {
		techs["Docker"] = true
	} else if name == "Chart.yaml" {
		techs["Helm"] = true
	} else if name == "playbook.yml" {
		techs["Ansible"] = true
	} else if name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts" {
		*hasJavaBuild = true
	}
}

func detectDatabaseMigratorLinks(name string, p *Project) {
	if name == "init.sql" || name == "migrate.sql" {
		p.Links = append(p.Links, DependencyLink{From: "Migrator", To: "Postgres", Type: "Init Script"})
	}
}

var ingressTargets = []struct {
	keywords []string
	target   string
}{
	{[]string{"frontend-nginx", "frontend-router"}, "Nginx"},
	{[]string{"frontend-angular", "frontend-angular-router"}, "Angular"},
	{[]string{"api-spring", "api-spring-router"}, "Spring"},
	{[]string{"api-quarkus", "api-quarkus-router"}, "Quarkus"},
	{[]string{"api-flask", "api-flask-router"}, "Flask"},
	{[]string{"api-dotnet", "api-dotnet-router"}, "DotNet"},
}

func detectIngressLinks(name, path string, p *Project) {
	if name == "routes.yaml" || name == "ingress.yaml" || name == "traefik.yml" || name == "traefik.yaml" {
		content, err := os.ReadFile(path)
		if err == nil {
			strContent := string(content)
			for _, tgt := range ingressTargets {
				for _, kw := range tgt.keywords {
					if strings.Contains(strContent, kw) {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: tgt.target, Type: "HTTP"})
						break
					}
				}
			}
		}
	}
}

func detectJavaFramework(name, path string, isSpringBoot, isQuarkus *bool) {
	if name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts" {
		content, err := os.ReadFile(path)
		if err == nil {
			strContent := string(content)
			if strings.Contains(strContent, "org.springframework.boot") {
				*isSpringBoot = true
			}
			if strings.Contains(strContent, "io.quarkus") {
				*isQuarkus = true
			}
		}
	}
}

func detectBackendLinksAndEntrypoints(name, path string, p *Project, hasSpringBootEntry, hasQuarkusEntry *bool) {
	if name == "application.properties" || name == "application.yml" || name == "application.yaml" {
		content, err := os.ReadFile(path)
		if err == nil {
			strContent := string(content)

			// Backend links
			if strings.Contains(strContent, "spring.data.redis.host") ||
				strings.Contains(strContent, "quarkus.redis.host-configured") ||
				(strings.Contains(strContent, "redis:") && strings.Contains(strContent, "host:")) {
				p.Links = append(p.Links, DependencyLink{From: "FRAMEWORK_PLACEHOLDER_REDIS", To: "Redis", Type: "Cache"})
			}

			if strings.Contains(strContent, "spring.rabbitmq.host") ||
				(strings.Contains(strContent, "rabbitmq:") && strings.Contains(strContent, "host:")) {
				p.Links = append(p.Links, DependencyLink{From: "FRAMEWORK_PLACEHOLDER_RABBITMQ", To: "RabbitMQ", Type: "Queue"})
			}

			if strings.Contains(strContent, "quarkus.datasource.db-kind=postgresql") ||
				strings.Contains(strContent, "quarkus.datasource.jdbc.url=jdbc:postgresql") ||
				strings.Contains(strContent, "spring.datasource.url=jdbc:postgresql") {
				p.Links = append(p.Links, DependencyLink{From: "FRAMEWORK_PLACEHOLDER_POSTGRES", To: "Postgres", Type: "JDBC"})
			}

			// Entrypoints
			if strings.Contains(strContent, "server.port") {
				*hasSpringBootEntry = true
			}
			if strings.Contains(strContent, "quarkus.http.port") {
				*hasQuarkusEntry = true
			}
		}
	}
}

func detectSourceEntrypoints(ext, path string, hasSpringBootEntry, hasQuarkusEntry *bool) {
	if ext == ".java" || ext == ".kt" {
		content, err := os.ReadFile(path)
		if err == nil {
			strContent := string(content)
			if strings.Contains(strContent, "@RestController") {
				*hasSpringBootEntry = true
			}
			if strings.Contains(strContent, "@Path") || strings.Contains(strContent, "@GET") || strings.Contains(strContent, "@POST") {
				*hasQuarkusEntry = true
			}
		}
	}
}

func shouldSkipDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "vendor" || name == "target" || name == "build"
}

func (a *Analyzer) analyzeRepository(repoPath string) (*Project, error) {
	p := &Project{
		Name: filepath.Base(repoPath),
		Path: repoPath,
	}

	techs := make(map[string]bool)
	hasJavaBuild := false
	isSpringBoot := false
	isQuarkus := false
	hasSpringBootEntry := false
	hasQuarkusEntry := false

	repoPathClean := filepath.Clean(repoPath)

	filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				if shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		name := d.Name()
		ext := filepath.Ext(path)
		isRoot := filepath.Dir(path) == repoPathClean

		if isRoot {
			detectRootTech(name, techs, &hasJavaBuild)
		}
		detectDatabaseMigratorLinks(name, p)
		detectIngressLinks(name, path, p)
		detectJavaFramework(name, path, &isSpringBoot, &isQuarkus)
		detectBackendLinksAndEntrypoints(name, path, p, &hasSpringBootEntry, &hasQuarkusEntry)
		detectSourceEntrypoints(ext, path, &hasSpringBootEntry, &hasQuarkusEntry)

		return nil
	})

	// Resolve technologies and links
	if hasJavaBuild {
		techs["Java/Kotlin"] = true
	}

	if isSpringBoot {
		techs["Spring Boot"] = true
		if hasSpringBootEntry {
			techs["HTTP Entrypoint (Spring)"] = true
		}
	}
	if isQuarkus {
		techs["Quarkus"] = true
		if hasQuarkusEntry {
			techs["HTTP Entrypoint (Quarkus)"] = true
		}
	}

	// Resolve placeholder links
	for i := range p.Links {
		if p.Links[i].From == "FRAMEWORK_PLACEHOLDER_REDIS" || p.Links[i].From == "FRAMEWORK_PLACEHOLDER_RABBITMQ" {
			p.Links[i].From = "Spring"
		} else if p.Links[i].From == "FRAMEWORK_PLACEHOLDER_POSTGRES" {
			p.Links[i].From = "Quarkus"
		}
	}

	for t := range techs {
		p.Technologies = append(p.Technologies, t)
	}

	return p, nil
}

func (a *Analyzer) mapDependencies(projects []*Project) {
	projectNames := make(map[string]bool)
	var allNames []string
	for _, p := range projects {
		projectNames[p.Name] = true
		allNames = append(allNames, p.Name)
	}

	var trie *ahocorasick.Trie
	if len(allNames) > 0 {
		trie = ahocorasick.NewTrieBuilder().AddStrings(allNames).Build()
	}

	var wg sync.WaitGroup
	for _, p := range projects {
		wg.Add(1)
		go func(proj *Project) {
			defer wg.Done()
			deps := a.findDependenciesInRepo(proj.Path, projectNames, proj.Name, trie)
			proj.Dependencies = deps
		}(p)
	}
	wg.Wait()
}

func (a *Analyzer) findDependenciesInRepo(repoPath string, projectNames map[string]bool, myName string, trie *ahocorasick.Trie) []string {
	found := make(map[string]bool)

	filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				if shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".go", ".js", ".ts", ".py", ".json", ".yaml", ".yml", ".env", ".java", ".kt", "":
			info, err := d.Info()
			if err != nil || info.Size() > 1024*1024 {
				return nil
			}

			func() {
				if trie != nil {
					content, err := os.ReadFile(filepath.Clean(path))
					if err != nil {
						return
					}
					matches := trie.Match(content)
					for _, match := range matches {
						pname := string(match.Match())
						if pname != myName && !found[pname] {
							found[pname] = true
						}
					}
				}
			}()
		}
		return nil
	})

	var deps []string
	for dep := range found {
		deps = append(deps, dep)
	}
	return deps
}
