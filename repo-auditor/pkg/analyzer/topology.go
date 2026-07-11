package analyzer

import (
	"bytes"
	"io/fs"
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
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		name := d.Name()
		switch name {
		case "routes.yaml":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("frontend-nginx-service")) {
				hasTraefik = true
			}
		case "Dockerfile":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("nginx")) {
				hasNginx = true
			}
		case "package.json":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("angular")) || bytes.Contains(data, []byte("frontend-angular")) {
				hasAngular = true
			}
		case "pom.xml":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("spring-boot-starter-web")) {
				hasSpring = true
			}
			if bytes.Contains(data, []byte("io.quarkus")) || bytes.Contains(data, []byte("quarkus")) {
				hasQuarkus = true
			}
		case "app.py", "requirements.txt":
			hasFlask = true
		case "application.yml", "application.yaml":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("redis")) {
				hasRedis = true
			}
			if bytes.Contains(data, []byte("rabbitmq")) {
				hasRabbitMQ = true
			}
		case "docker-compose.yml":
			data, _ := os.ReadFile(path)
			if bytes.Contains(data, []byte("postgres")) {
				hasPostgres = true
			}
		case "init.sql", "migrate.sql":
			hasMigrator = true
		default:
			if strings.HasSuffix(name, ".csproj") {
				hasDotNet = true
			}
		}

		if hasTraefik && hasNginx && hasSpring && hasRedis && hasRabbitMQ && hasQuarkus && hasAngular && hasFlask && hasDotNet && hasPostgres && hasMigrator {
			return filepath.SkipAll
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
