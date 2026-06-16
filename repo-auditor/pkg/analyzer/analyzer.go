package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"repo-auditor/pkg/security"

	"github.com/go-git/go-git/v5"
)

type Project struct {
	Name         string
	Path         string
	Technologies []string
	Dependencies []string
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

func (a *Analyzer) Analyze() ([]*Project, *security.SecurityReport, error) {
	paths, err := a.findRepositories(a.RootPath)
	if err != nil {
		return nil, nil, err
	}

	secReport := &security.SecurityReport{}
	security.RunTrivyScan(a.RootPath, secReport)

	projects := a.analyzeConcurrent(paths, secReport)
	a.mapDependencies(projects)

	return projects, secReport, nil
}

func (a *Analyzer) findRepositories(root string) ([]string, error) {
	var repos []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == ".git" {
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

					var localReport security.SecurityReport
					security.RunGitleaksScan(path, &localReport)

					dockerfilePath := filepath.Join(path, "Dockerfile")
					if _, err := os.Stat(dockerfilePath); err == nil {
						security.RunHadolintScan(dockerfilePath, p.Name, &localReport)
					}

					// Check Helm and trigger kube-linter
					chartPath := filepath.Join(path, "Chart.yaml")
					templatesPath := filepath.Join(path, "templates")
					_, errChart := os.Stat(chartPath)
					_, errTemplates := os.Stat(templatesPath)
					if errChart == nil || errTemplates == nil {
						security.RunKubeLinterScan(path, p.Name, &localReport)
					}

					// Check go.mod and pom.xml for licenses
					goModPath := filepath.Join(path, "go.mod")
					if _, err := os.Stat(goModPath); err == nil {
						security.RunLicenseScan(goModPath, p.Name, false, &localReport)
					}
					pomPath := filepath.Join(path, "pom.xml")
					if _, err := os.Stat(pomPath); err == nil {
						security.RunLicenseScan(pomPath, p.Name, true, &localReport)
					}

					mu.Lock()
					secReport.GitleaksSecrets = append(secReport.GitleaksSecrets, localReport.GitleaksSecrets...)
					secReport.HadolintIssues = append(secReport.HadolintIssues, localReport.HadolintIssues...)
					secReport.KubeLinterIssues = append(secReport.KubeLinterIssues, localReport.KubeLinterIssues...)
					secReport.CopyleftLicenses = append(secReport.CopyleftLicenses, localReport.CopyleftLicenses...)

					if localReport.HadolintSkipped {
						secReport.HadolintSkipped = true
					}
					if localReport.KubeLinterSkipped {
						secReport.KubeLinterSkipped = true
					}
					mu.Unlock()
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

func (a *Analyzer) analyzeRepository(repoPath string) (*Project, error) {
	p := &Project{
		Name: filepath.Base(repoPath),
		Path: repoPath,
	}

	techs := make(map[string]bool)
	hasJavaBuild := false

	entries, err := os.ReadDir(repoPath)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				name := e.Name()
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
		}
	}

	isSpringBoot := false
	isQuarkus := false

	if hasJavaBuild {
		techs["Java/Kotlin"] = true
		filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				if info != nil && info.IsDir() {
					name := info.Name()
					if name == ".git" || name == "node_modules" || name == "vendor" {
						return filepath.SkipDir
					}
				}
				return nil
			}

			name := info.Name()
			if name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts" {
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
			}
			return nil
		})
	}

	if isSpringBoot {
		techs["Spring Boot"] = true
		if a.hasSpringBootEntrypoint(repoPath) {
			techs["HTTP Entrypoint (Spring)"] = true
		}
	}
	if isQuarkus {
		techs["Quarkus"] = true
		if a.hasQuarkusEntrypoint(repoPath) {
			techs["HTTP Entrypoint (Quarkus)"] = true
		}
	}

	for t := range techs {
		p.Technologies = append(p.Technologies, t)
	}

	return p, nil
}

func (a *Analyzer) hasSpringBootEntrypoint(repoPath string) bool {
	found := false
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if found || err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "target" || name == "build" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		name := info.Name()
		ext := filepath.Ext(path)

		if ext == ".java" || ext == ".kt" {
			file, err := os.Open(path)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), "@RestController") {
						found = true
						break
					}
				}
				file.Close()
			}
		} else if name == "application.properties" || name == "application.yml" || name == "application.yaml" {
			file, err := os.Open(path)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), "server.port") {
						found = true
						break
					}
				}
				file.Close()
			}
		}
		return nil
	})
	return found
}

func (a *Analyzer) hasQuarkusEntrypoint(repoPath string) bool {
	found := false
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if found || err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "target" || name == "build" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		name := info.Name()
		ext := filepath.Ext(path)

		if ext == ".java" || ext == ".kt" {
			file, err := os.Open(path)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "@Path") || strings.Contains(line, "@GET") || strings.Contains(line, "@POST") {
						found = true
						break
					}
				}
				file.Close()
			}
		} else if name == "application.properties" {
			file, err := os.Open(path)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), "quarkus.http.port") {
						found = true
						break
					}
				}
				file.Close()
			}
		}
		return nil
	})
	return found
}

func (a *Analyzer) mapDependencies(projects []*Project) {
	projectNames := make(map[string]bool)
	for _, p := range projects {
		projectNames[p.Name] = true
	}

	var wg sync.WaitGroup
	for _, p := range projects {
		wg.Add(1)
		go func(proj *Project) {
			defer wg.Done()
			deps := a.findDependenciesInRepo(proj.Path, projectNames, proj.Name)
			proj.Dependencies = deps
		}(p)
	}
	wg.Wait()
}

func (a *Analyzer) findDependenciesInRepo(repoPath string, projectNames map[string]bool, myName string) []string {
	found := make(map[string]bool)

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

		ext := filepath.Ext(path)
		if ext == ".go" || ext == ".js" || ext == ".ts" || ext == ".py" || ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".env" || ext == ".java" || ext == ".kt" || ext == "" {
			if info.Size() > 1024*1024 {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				for pname := range projectNames {
					if pname != myName && !found[pname] {
						if strings.Contains(line, pname) {
							found[pname] = true
						}
					}
				}
			}
		}
		return nil
	})

	var deps []string
	for dep := range found {
		deps = append(deps, dep)
	}
	return deps
}
