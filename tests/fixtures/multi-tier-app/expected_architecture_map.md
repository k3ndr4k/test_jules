graph TD
    Client([🌐 Internet]) -->|HTTP/HTTPS| Traefik[💧 Ingress: Traefik]

    Traefik -->|Proxy: /| Angular[🅰️ Frontend: Angular]
    Traefik -->|Proxy: /api/quarkus| Quarkus[⚛️ API: Quarkus]
    Traefik -->|Proxy: /api/flask| Flask[🐍 API: Python/Flask]
    Traefik -->|Proxy: /api/dotnet| DotNet[🟣 API: .NET]

    Quarkus -->|JDBC / Port 5432| Postgres[(🐘 BDD: PostgreSQL 13.2)]
    Migrator[📜 DB Migrator: SQL] -->|Init Script| Postgres
