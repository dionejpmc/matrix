> Plataforma centralizada para geração, armazenamento, análise e rastreamento de Software Bill of Materials (SBOM), com foco em gestão de vulnerabilidades e rastreamento de dependências por unidade de negócio.

---

## Sumário

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e execução](#instalação-e-execução)
- [Variáveis de ambiente](#variáveis-de-ambiente)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Modelo de dados](#modelo-de-dados)
- [Pipeline de scan](#pipeline-de-scan)
- [RBAC — Controle de acesso](#rbac--controle-de-acesso)
- [API REST](#api-rest)
- [Testes](#testes)
- [Segurança](#segurança)
- [Roadmap](#roadmap)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

---

## Visão Geral

O **Matrix SBOM Manager** permite que equipes de segurança e engenharia:

- Gerem SBOMs automaticamente a partir de imagens RootFS (containers, sistemas embarcados)
- Detectem vulnerabilidades conhecidas (CVEs) correlacionadas com os componentes do SBOM
- Rastreiem dependências como um grafo navegável, identificando impacto transitivo de CVEs
- Gerenciem o ciclo completo de triagem de vulnerabilidades com histórico de auditoria
- Organizem produtos por hierarquia de Unidade de Negócio (BU) → Família → Produto

```
┌─────────────────────────────────────────────────────────────┐
│                     Matrix SBOM Manager                     │
│                                                             │
│  Upload RootFS → Syft → SBOM CycloneDX → Neo4j (grafo)     │
│                              ↓                              │
│                  Grype → CVEs → PostgreSQL (triagem)        │
│                              ↓                              │
│         Dashboard · Lista · Grafo · Alertas · Relatórios    │
└─────────────────────────────────────────────────────────────┘
```

---

## Funcionalidades

### Core
- **Geração de SBOM** via [Syft](https://github.com/anchore/syft) a partir de RootFS (tar, tar.gz, squashfs)
- **Scan de vulnerabilidades** via [Grype](https://github.com/anchore/grype) com correlação NVD e OSV
- **Grafo de dependências** armazenado no Neo4j com consultas Cypher
- **Formatos suportados**: CycloneDX JSON, CycloneDX XML, SPDX JSON

### Organização
- Hierarquia **BU → Família → Produto → RootFS**
- Políticas de severidade configuráveis por BU
- Métricas de risco agregadas por BU e família

### Segurança e Compliance
- **RBAC** com 5 papéis: Admin, Security Analyst, BU Manager, Contributor, Viewer
- Triagem de CVEs com fluxo: Aberto → Em análise → Mitigado → Aceito → Falso positivo
- Histórico imutável de todas as alterações de triagem
- Alertas automáticos para novas CVEs em componentes catalogados

### Visualização
- **Modo lista**: tabela de componentes com painel de CVEs expansível inline (HTMX)
- **Modo grafo**: Cytoscape.js com coloração por severidade e modal de detalhes
- **Dashboard**: métricas por BU, contadores por severidade, últimos scans

---

## Arquitetura

O sistema é composto por **7 containers Docker** orquestrados via Docker Compose:

```
                        ┌──────────────────────────────┐
                        │         matrix_net           │
                        │   (rede interna isolada)     │
                        │                              │
   Usuário ──HTTPS──►   ┌───────────┐                  │
                        │ matrix-app│◄─────────────────┤
                        │  Django 5 │                  │
                        └┬──────────┘                  │
                         │                             │
              ┌──────────┼──────────┬──────────┐       │
              ▼          ▼          ▼          ▼       │
        ┌──────────┐ ┌───────┐ ┌────────┐ ┌────────┐   │
        │matrix-db │ │neo4j  │ │ redis  │ │ worker │   │
        │Postgres15│ │  5    │ │   7    │ │Celery  │   │
        └──────────┘ └───────┘ └────────┘ └───┬────┘   │
                                               │       │
                                    ┌──────────┴──┐    │
                                    │  /rootfs    │    │
                                    │  (volume)   │    │
                                    └──┬───────┬──┘    │
                                       ▼       ▼       │
                                  ┌───────┐ ┌───────┐  │
                                  │ syft  │ │ grype │  │
                                  └───────┘ └───────┘  │
                                                       │
                                  └────────────────────┘
```

| Container | Imagem | Função |
|---|---|---|
| `matrix-app` | Python 3.12 + Django 5 | Aplicação principal |
| `matrix-db` | postgres:15-alpine | Dados relacionais |
| `matrix-graph` | neo4j:5-community | Grafo de SBOMs |
| `matrix-redis` | redis:7-alpine | Broker Celery |
| `matrix-worker` | Python 3.12 + Celery | Jobs assíncronos |
| `matrix-syft` | anchore/syft | Geração de SBOM |
| `matrix-grype` | anchore/grype | Scan de CVEs |

---

## Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) >= 24
- [Docker Compose](https://docs.docker.com/compose/) >= 2.20
- 4 GB de RAM disponível para os containers
- 20 GB de espaço em disco (para o volume de RootFS)

---

## Instalação e execução

### 1. Clone o repositório

```bash
git clone https://github.com/sua-org/matrix-sbom-manager.git
cd matrix-sbom-manager
```

### 2. Configure as variáveis de ambiente

```bash
cp .env.example .env
# Edite o .env com suas credenciais
```

### 3. Suba os containers

```bash
docker compose up -d
```

### 4. Execute as migrations

```bash
docker compose exec app python manage.py migrate
```

### 5. Crie o superusuário

```bash
docker compose exec app python manage.py createsuperuser
```

### 6. Acesse a aplicação

| Serviço | URL |
|---|---|
| Aplicação | http://localhost:8000 |
| Django Admin | http://localhost:8000/admin |
| Neo4j Browser | http://localhost:7474 |

---

## Variáveis de Ambiente

Copie `.env.example` para `.env` e preencha os valores:

```env
# Django
SECRET_KEY=troque-por-uma-chave-segura-com-50-chars
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_SETTINGS_MODULE=config.settings.development

# PostgreSQL
POSTGRES_DB=matrix
POSTGRES_USER=matrix
POSTGRES_PASSWORD=senha-segura-aqui
DATABASE_URL=postgresql://matrix:senha-segura-aqui@db:5432/matrix

# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=senha-neo4j-aqui

# Redis / Celery
REDIS_URL=redis://:senha-redis@redis:6379/0
CELERY_BROKER_URL=redis://:senha-redis@redis:6379/0
CELERY_RESULT_BACKEND=redis://:senha-redis@redis:6379/1
REDIS_PASSWORD=senha-redis

# Storage
ROOTFS_STORAGE_PATH=/rootfs
MAX_UPLOAD_SIZE_MB=4096

# Containers de scan
SYFT_CONTAINER=matrix-syft-1
GRYPE_CONTAINER=matrix-grype-1
```

> ⚠️ **Nunca commite o arquivo `.env` com valores reais.** Ele está no `.gitignore`.

---

## Estrutura do Projeto

```
matrix/
├── app/
│   ├── config/               # Settings, URLs raiz, WSGI/ASGI
│   │   └── settings/
│   │       ├── base.py       # Settings compartilhados
│   │       ├── development.py
│   │       └── production.py
│   ├── apps/
│   │   ├── accounts/         # Autenticação, usuários, RBAC
│   │   ├── organizations/    # BU, Família, Produto
│   │   ├── rootfs/           # Upload e pipeline de scan
│   │   ├── sbom/             # Ingestão e visualização de SBOMs
│   │   ├── vulnerabilities/  # Triagem de CVEs e políticas
│   │   └── dashboard/        # Dashboard e métricas
│   ├── core/
│   │   ├── neo4j_client.py   # Conexão com Neo4j (singleton)
│   │   ├── permissions.py    # Mixins e decorators RBAC
│   │   ├── storage.py        # Persistência de arquivos RootFS
│   │   └── exceptions.py     # Exceções customizadas
│   ├── tasks/
│   │   ├── celery.py         # Configuração do Celery
│   │   ├── scan_tasks.py     # Pipeline: Syft → Grype → Neo4j
│   │   └── notification_tasks.py
│   ├── api/                  # Endpoints JSON/HTMX
│   ├── templates/            # Templates Django (HTMX + Alpine.js)
│   └── static/               # CSS e JS estáticos
├── docker/
│   ├── app/Dockerfile
│   ├── syft/Dockerfile
│   └── grype/Dockerfile
├── scripts/
│   ├── entrypoint.sh         # Aguarda DB, roda migrations, collectstatic
│   └── wait-for-it.sh
├── docker-compose.yml
├── .env.example
└── CLAUDE.md                 # Contexto para desenvolvimento com Claude Code
```

---

## Modelo de Dados

### PostgreSQL (dados relacionais)

```
Organization
└── BusinessUnit (BU)
    └── Family
        └── Product
            └── RootFS ──► ScanLog
                └── VulnerabilityTriage ──► TriageHistory

User ──► UserBUMembership (user + bu + role)
```

### Neo4j (grafo de dependências)

```cypher
(:SBOM)-[:CONTAINS]->(:Component)
(:Component)-[:DEPENDS_ON]->(:Component)
(:Component)-[:HAS_VULNERABILITY]->(:CVE)
(:Component)-[:LICENSED_UNDER]->(:License)
```

**Exemplo — encontrar todos os projetos afetados por uma CVE crítica:**

```cypher
MATCH (s:SBOM)-[:CONTAINS]->(c:Component)-[:HAS_VULNERABILITY]->(v:CVE)
WHERE v.cveId = 'CVE-2021-44228' AND v.severity = 'CRITICAL'
RETURN s.name, s.version, c.name, c.version
ORDER BY s.name
```

**Exemplo — dependências transitivas de um componente:**

```cypher
MATCH path = (s:SBOM {sbomId: $sbomId})-[:CONTAINS*1..5]->(c:Component)
WHERE c.name = 'openssl'
RETURN path
```

---

## Pipeline de Scan

Após o upload de um RootFS, o pipeline assíncrono (Celery) executa:

```
Upload RootFS
     │
     ▼
[PENDING] ──► Validação: extensão, magic bytes, tamanho
     │
     ▼
[GENERATING_SBOM] ──► docker exec matrix-syft-1 syft /rootfs/<uuid>
     │                  Output: sbom_<uuid>.json (CycloneDX)
     ▼
[SCANNING_VULNS] ──► docker exec matrix-grype-1 grype sbom:/rootfs/sbom_<uuid>.json
     │                 Output: grype_<uuid>.json
     ▼
[INGESTING] ──► Parse CycloneDX → Neo4j (:SBOM, :Component, :DEPENDS_ON)
     │      └─► Parse Grype → Neo4j (:CVE, :HAS_VULNERABILITY)
     │      └─► PostgreSQL: VulnerabilityTriage para CVEs CRITICAL/HIGH
     ▼
[COMPLETED] ──► Notificação ao usuário

Em qualquer falha → [ERROR] com mensagem em ScanLog
```

---

## RBAC — Controle de Acesso


> A verificação de BU é sempre feita **server-side** via `BUAccessMixin`. IDs de BU enviados pelo cliente nunca são confiados sem validação.

---

## API REST

Documentação interativa disponível em `/api/docs/` (Swagger UI).

### Endpoints principais

| Método | Endpoint | Descrição |
|---|---|---|
| `GET` | `/api/sbom/<rootfs_id>/graph-data/` | JSON `{nodes, edges}` para Cytoscape.js |
| `GET` | `/api/sbom/<rootfs_id>/component/<purl>/vulns/` | CVEs de um componente (HTML parcial HTMX) |
| `PATCH` | `/api/vulnerabilities/<triage_id>/status/` | Atualiza status de triagem |
| `GET` | `/api/rootfs/<id>/status/` | Status atual do pipeline (HTML parcial HTMX) |

### Autenticação na API

Autenticação por **sessão Django** (mesmo cookie do browser). Para integração CI/CD, use API Keys com escopo mínimo (configurável no admin).

---

## Testes

```bash
# Rodar todos os testes
docker compose exec app pytest

# Com cobertura
docker compose exec app pytest --cov=apps --cov-report=term-missing

# Apenas um app
docker compose exec app pytest tests/accounts/

# Apenas testes de RBAC
docker compose exec app pytest tests/accounts/test_rbac.py -v
```

### Estrutura de testes

```
tests/
├── conftest.py              # Fixtures: users, bu, family, product, rootfs
├── accounts/
│   └── test_rbac.py         # Todas as combinações role × endpoint
├── organizations/
│   └── test_models.py
├── rootfs/
│   └── test_upload.py
├── sbom/
│   ├── test_parser.py       # Parser CycloneDX com fixture JSON
│   └── test_views.py
└── vulnerabilities/
    ├── test_parser.py       # Parser Grype com fixture JSON
    └── test_triage.py
```

---

## Segurança

### Controles implementados

| Controle | Implementação |
|---|---|
| Hash de senhas | Argon2id via `django-argon2` |
| Proteção CSRF | Token Django em todos os forms e requests HTMX |
| Cookies seguros | `Secure + HttpOnly + SameSite=Strict` em produção |
| Injeção Cypher | Queries 100% parametrizadas em `core/neo4j_client.py` |
| IDOR | `BUAccessMixin` em todas as views com dados de BU |
| Command injection | UUID interno como filename; nunca o nome original |
| Upload malicioso | Validação de magic bytes + extensão antes de aceitar |
| Neo4j exposto | Porta 7687 restrita à rede interna `matrix_net` |
| Redis | Senha obrigatória via `REDIS_PASSWORD` |
| Logs de auditoria | Toda ação crítica logada com user, timestamp e IP |

### Modelagem de ameaças

A modelagem completa de ameaças utilizando a metodologia **PASTA** (Process for Attack Simulation and Threat Analysis) está disponível em [`docs/threat-model.md`](docs/threat-model.md), cobrindo:

- 10 ameaças identificadas (4 críticas, 4 altas, 2 médias)
- Árvores de ataque para 4 vetores principais
- Matriz de risco com impacto × probabilidade
- Contramedidas mapeadas por fase de implementação

---

## Roadmap

| Fase | Versão | Escopo |
|---|---|---|
| ✅ Infraestrutura | MVP | Docker Compose, PostgreSQL, Neo4j, Redis, Celery |
| 🔄 Autenticação | MVP | Login, RBAC, gestão de usuários |
| 🔄 Organizações | MVP | BU, Família, Produto |
| ⏳ Pipeline | MVP | Upload RootFS, Syft, Grype, ingestão Neo4j |
| ⏳ Visualização | v1.1 | Lista com CVEs HTMX, grafo Cytoscape.js |
| ⏳ Vulnerabilidades | v1.1 | Dashboard, triagem, histórico |
| ⏳ Licenças e políticas | v1.2 | Motor de políticas por BU, gestão de licenças SPDX |
| ⏳ API e integrações | v1.2 | OpenAPI docs, webhooks, API Keys CI/CD |
| ⏳ Kubernetes e SSO | v2.0 | Helm chart, OIDC/SAML, Prometheus, Grafana |

---

## Contribuindo

1. Faça um fork do repositório
2. Crie uma branch para sua feature: `git checkout -b feat/nome-da-feature`
3. Siga as convenções de código:
   - Python: PEP 8 + type hints + docstrings em métodos públicos
   - Linting: `ruff check .` e `black .` antes de commitar
   - Queries Neo4j: sempre parametrizadas, nunca f-strings com dados externos
4. Escreva testes para o que implementou
5. Abra um Pull Request com descrição do que foi feito e por quê

### Comandos úteis para desenvolvimento

```bash
# Ver logs de todos os containers
docker compose logs -f

# Apenas logs do worker Celery
docker compose logs -f worker

# Acessar o shell Django
docker compose exec app python manage.py shell

# Criar nova migration após alterar models
docker compose exec app python manage.py makemigrations

# Executar linting
docker compose exec app ruff check .
docker compose exec app black --check .

# Acessar o Neo4j Browser
open http://localhost:7474
# Credenciais: neo4j / <NEO4J_PASSWORD do .env>
```

---

## Licença

Distribuído sob a licença MIT. Veja [`LICENSE`](LICENSE) para mais detalhes.

---

<div align="center">
  <sub>Construído com Django · Neo4j · Syft · Grype · HTMX · Tailwind · Celery</sub>
</div>
