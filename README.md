# Documentation WAF ModSecurity + OWASP CRS pour N8N & Stack de Monitoring

## 📋 Vue d'ensemble

Cette solution déploie :

* Un **Web Application Firewall (WAF)** basé sur ModSecurity et OWASP Core Rule Set (CRS) pour protéger une instance **N8N**.
* Une stack **ELK (Elasticsearch, Logstash, Kibana)** pour la collecte et l'analyse des logs.
* **Prometheus** et **Grafana** pour le monitoring des performances et métriques.
* Un cache **Redis** pour optimiser N8N.

Le WAF agit comme un proxy inverse avec terminaison SSL et filtrage avancé des requêtes.

## 🏗️ Architecture de la solution

```mermaid
graph TB
    %% Style definitions
    classDef internet fill:#ff6b6b,stroke:#d63447,stroke-width:2px,color:#fff
    classDef waf fill:#4ecdc4,stroke:#26a69a,stroke-width:2px,color:#fff
    classDef backend fill:#45b7d1,stroke:#2196f3,stroke-width:2px,color:#fff
    classDef database fill:#96ceb4,stroke:#00b894,stroke-width:2px,color:#fff
    classDef cache fill:#f6b93b,stroke:#e58e26,stroke-width:2px,color:#fff
    classDef logs fill:#a29bfe,stroke:#6c5ce7,stroke-width:2px,color:#fff
    classDef monitoring fill:#78e08f,stroke:#38ada9,stroke-width:2px,color:#fff

    %% External traffic
    Internet[🌐 Internet<br/>HTTP/HTTPS]:::internet

    %% WAF
    subgraph WAF [🛡️ WAF Gateway]
        WAF_NGINX[🔄 Nginx Reverse Proxy<br/>SSL Termination + Redirect HTTP→HTTPS]:::waf
        WAF_MODSEC[🛡️ ModSecurity + OWASP CRS<br/>Paranoia Level 2]:::waf
    end

    %% Backend
    subgraph BACKEND [📊 Backend Services]
        N8N[🤖 N8N Automation<br/>Port 5678]:::backend
        DB[(🐘 PostgreSQL 15)]:::database
        REDIS[⚡ Redis Cache]:::cache
    end

    %% Logs & Monitoring
    subgraph LOGS [📊 Logs & Analytics]
        ES[(🔍 Elasticsearch)]:::logs
        LS[📥 Logstash]:::logs
        KB[📊 Kibana]:::logs
    end

    subgraph MON[📈 Monitoring]
        PROM[📡 Prometheus]:::monitoring
        GRAF[📊 Grafana]:::monitoring
    end

    %% Flows
    Internet --> WAF_NGINX --> WAF_MODSEC --> N8N
    N8N --> DB
    N8N --> REDIS
    WAF_MODSEC -. logs .-> LS --> ES --> KB
    PROM --> GRAF
```

## 🔧 Composants techniques

### 1. WAF Gateway (ModSecurity + Nginx)

* **Image** : `owasp/modsecurity-crs:nginx`
* **Ports** : 80 (HTTP) → 443 (HTTPS)
* **Fonctions** :

  * Terminaison SSL
  * Redirection automatique vers HTTPS
  * Filtrage OWASP CRS niveau 2
  * Audit logs détaillés

### 2. N8N

* **Image** : `n8nio/n8n:latest`
* **DB** : PostgreSQL 15
* **Cache** : Redis
* **Sécurité** : Authentification Basic activée

### 3. Stack ELK

* **Elasticsearch** : Indexation des logs
* **Logstash** : Ingestion et transformation
* **Kibana** : Visualisation

### 4. Monitoring

* **Prometheus** : Collecte métriques
* **Grafana** : Dashboards personnalisés

## ⚙️ Configuration

* **Variables d’environnement N8N** dans `.env`
* **Certificats SSL** dans `config/waf/certs`
* **Règles ModSecurity** dans `config/waf/modsecurity.d/owasp-crs/custom_rules`
* **Pipeline Logstash** dans `config/SIEM/logstash/pipeline`
* **Prometheus** dans `prometheus/prometheus.yml`
* **Grafana** dashboards & datasources dans `grafana/`

## 🚀 Déploiement

```bash
docker-compose up -d
docker-compose ps
```

Vérifier :

* WAF : `https://localhost` (redirection HTTP→HTTPS)
* Kibana : `http://localhost:5601`
* Grafana : `http://localhost:3000`
* Prometheus : `http://localhost:9090`

## 🧪 Tests rapides

* Injection SQL : `curl -k "https://localhost/?id=1' OR '1'='1"`
* XSS : `curl -k "https://localhost/?search=<script>alert(1)</script>"`

Les deux doivent être bloqués (HTTP 403).

## 📊 Logs

```bash
docker exec waf-gateway tail -f /var/log/modsecurity_audit.log
docker exec logstash tail -f /usr/share/logstash/logs/logstash-plain.log
```

## 🔒 Sécurité

Protège contre :

* SQLi, XSS, CSRF, Path Traversal
* Injection de commandes
* User-agents malveillants
* Méthodes HTTP non autorisées
