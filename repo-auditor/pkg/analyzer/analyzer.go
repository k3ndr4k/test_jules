package analyzer

import (
	"bufio"
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

	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "target" || name == "build" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		name := info.Name()
		ext := filepath.Ext(path)
		isRoot := filepath.Dir(path) == repoPathClean

		// Root level technology detection
		if isRoot {
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
				hasJavaBuild = true
			}
		}

		// Database Migrator Links
		if name == "init.sql" || name == "migrate.sql" {
			p.Links = append(p.Links, DependencyLink{From: "Migrator", To: "Postgres", Type: "Init Script"})
		}

		// Ingress links detection
		if name == "routes.yaml" || name == "ingress.yaml" || name == "traefik.yml" || name == "traefik.yaml" {
			func() {
				content, err := os.ReadFile(path)
				if err == nil {
					strContent := string(content)
					if strings.Contains(strContent, "frontend-nginx") || strings.Contains(strContent, "frontend-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "Nginx", Type: "HTTP"})
					}
					if strings.Contains(strContent, "frontend-angular") || strings.Contains(strContent, "frontend-angular-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "Angular", Type: "HTTP"})
					}
					if strings.Contains(strContent, "api-spring") || strings.Contains(strContent, "api-spring-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "Spring", Type: "HTTP"})
					}
					if strings.Contains(strContent, "api-quarkus") || strings.Contains(strContent, "api-quarkus-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "Quarkus", Type: "HTTP"})
					}
					if strings.Contains(strContent, "api-flask") || strings.Contains(strContent, "api-flask-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "Flask", Type: "HTTP"})
					}
					if strings.Contains(strContent, "api-dotnet") || strings.Contains(strContent, "api-dotnet-router") {
						p.Links = append(p.Links, DependencyLink{From: "Traefik", To: "DotNet", Type: "HTTP"})
					}
				}
			}()
		}

		// Java Framework detection
		if name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts" {
			func() {
				content, err := os.ReadFile(path)
				if err == nil {
					strContent := string(content)
					if strings.Contains(strContent, "org.springframework.boot") {
						isSpringBoot = true
					}
					if strings.Contains(strContent, "io.quarkus") {
						isQuarkus = true
					}
				}
			}()
		}

		// Backend links and entrypoint detection in properties
		if name == "application.properties" || name == "application.yml" || name == "application.yaml" {
			func() {
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
						hasSpringBootEntry = true
					}
					if strings.Contains(strContent, "quarkus.http.port") {
						hasQuarkusEntry = true
					}
				}
			}()
		}

		// Java/Kotlin source entrypoints
		if ext == ".java" || ext == ".kt" {
			func() {
				file, err := os.Open(path)
				if err != nil {
					return
				}
				defer file.Close()
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "@RestController") {
						hasSpringBootEntry = true
					}
					if strings.Contains(line, "@Path") || strings.Contains(line, "@GET") || strings.Contains(line, "@POST") {
						hasQuarkusEntry = true
					}
				}
			}()
		}

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

	// Fix placeholder links
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
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "target" || name == "build" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".go" || ext == ".js" || ext == ".ts" || ext == ".py" || ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".env" || ext == ".java" || ext == ".kt" || ext == "" {
			info, err := d.Info()
			if err != nil || info.Size() > 1024*1024 {
				return nil
			}

			func() {
				file, err := os.Open(filepath.Clean(path))
				if err != nil {
					return
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					if trie != nil {
						matches := trie.MatchString(line)
						for _, match := range matches {
							pname := string(match.Match())
							if pname != myName && !found[pname] {
								found[pname] = true
							}
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
