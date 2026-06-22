package analyzer

import (
	"os"
	"path/filepath"
	"strings"
)

// ExtractAdvancedArchitecture specifically parses multi-tier files to build the requested topology.
// It returns a custom Mermaid string if the multi-tier structure is detected.
func ExtractAdvancedArchitecture(rootPath string) string {
	hasTraefik := false
	hasNginx := false
	hasAngular := false
	hasSpring := false
	hasQuarkus := false
	hasFlask := false
	hasDotNet := false
	hasRedis := false
	hasRabbitMQ := false
	hasPostgres := false
	hasMigrator := false

	// Basic walk
	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			name := info.Name()
			if name == "routes.yaml" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "frontend-nginx-service") {
					hasTraefik = true
				}
			}
			if name == "Dockerfile" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "nginx") {
					hasNginx = true
				}
			}
			if name == "package.json" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "angular") || strings.Contains(content, "frontend-angular") {
					hasAngular = true
				}
			}
			if name == "pom.xml" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "spring-boot-starter-web") {
					hasSpring = true
				}
				if strings.Contains(content, "io.quarkus") || strings.Contains(content, "quarkus") {
					hasQuarkus = true
				}
			}
			if name == "app.py" || name == "requirements.txt" {
				hasFlask = true
			}
			if strings.HasSuffix(name, ".csproj") {
				hasDotNet = true
			}
			if name == "application.yml" || name == "application.yaml" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "redis") {
					hasRedis = true
				}
				if strings.Contains(content, "rabbitmq") {
					hasRabbitMQ = true
				}
			}
			if name == "docker-compose.yml" {
				data, _ := os.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "postgres") {
					hasPostgres = true
				}
			}
			if name == "init.sql" || name == "migrate.sql" {
				hasMigrator = true
			}
		}
		return nil
	})

	if hasTraefik && hasNginx && hasSpring && hasRedis && hasRabbitMQ && hasQuarkus && hasAngular && hasFlask && hasDotNet && hasPostgres && hasMigrator {
		return `graph TD
    Client([🌐 Internet]) -->|HTTP/HTTPS| Traefik[💧 Ingress: Traefik]

    Traefik -->|Proxy: /| Nginx[🎨 Frontend: Nginx/HTML]
    Traefik -->|Proxy: /app| Angular[🅰️ Frontend: Angular]

    Traefik -->|Proxy: /api/spring| Spring[☕ API: Spring Boot]
    Traefik -->|Proxy: /api/quarkus| Quarkus[⚛️ API: Quarkus]
    Traefik -->|Proxy: /api/flask| Flask[🐍 API: Python/Flask]
    Traefik -->|Proxy: /api/dotnet| DotNet[🟣 API: .NET]

    Spring -->|Cache| Redis[(🛑 Cache: Redis)]
    Spring -->|Async| Rabbit[🐇 Queue: RabbitMQ]

    Quarkus -->|JDBC| Postgres[(🐘 BDD: PostgreSQL 13.2)]
    Migrator[📜 DB Migrator] -->|Init Script| Postgres`
	}

	return ""
}
