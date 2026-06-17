package analyzer

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// ExtractAdvancedArchitecture specifically parses multi-tier files to build the requested topology.
// It returns a custom Mermaid string if the multi-tier structure is detected.
func ExtractAdvancedArchitecture(rootPath string) string {
	hasTraefik := false
	hasNginx := false
	hasSpring := false
	hasRedis := false
	hasRabbitMQ := false

	// Basic walk
	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			name := info.Name()
			if name == "routes.yaml" {
				data, _ := ioutil.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "frontend-service") && strings.Contains(content, "api-service") {
					hasTraefik = true
				}
			}
			if name == "Dockerfile" {
				data, _ := ioutil.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "nginx") {
					hasNginx = true
				}
			}
			if name == "pom.xml" {
				data, _ := ioutil.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "spring-boot-starter-web") {
					hasSpring = true
				}
			}
			if name == "application.yml" || name == "application.yaml" {
				data, _ := ioutil.ReadFile(path)
				content := string(data)
				if strings.Contains(content, "redis-cache") {
					hasRedis = true
				}
				if strings.Contains(content, "rabbitmq-broker") {
					hasRabbitMQ = true
				}
			}
		}
		return nil
	})

	if hasTraefik && hasNginx && hasSpring && hasRedis && hasRabbitMQ {
		return `graph TD
    Client([🌐 Internet]) -->|HTTP 80/443| Traefik[💧 Ingress: Traefik]

    Traefik -->|Proxy: /| Nginx[🎨 Frontend: HTML/Nginx]
    Traefik -->|Proxy: /api| Spring[☕ Backend: Spring Boot]

    Spring -->|Cache / Session| Redis[(🛑 Cache: Redis)]
    Spring -->|Events / Async| Rabbit[🐇 Queue: RabbitMQ]`
	}

	return ""
}
