# WebShield — Architecture & Implementation Blueprint

## Executive Overview
**WebShield** is a defensive cybersecurity and vulnerability assessment platform built specifically for small organizations. It automates security scanning, detects security misconfigurations, analyzes OWASP Top 10 compliance, evaluates TLS & HTTP security headers, and generates actionable, evidence-backed security reports with remediation guidance.

---

## Architecture Diagram

```mermaid
flowchart TB
    subgraph Client ["Frontend (React 18 + TypeScript)"]
        UI["Cybersecurity SaaS Dashboard"]
        ScanForm["New Scan Form + Auth Check"]
        LiveView["Real-time Progress Tracker"]
        ReportView["Scan Results & Reports"]
    end

    subgraph API ["Backend API (Node.js + Express)"]
        Router["REST API Routes & Controllers"]
        AuthMiddleware["JWT Auth & RBAC"]
        SSRFGuardian["SSRF & Target Guardian"]
        RateLimiter["Redis Rate Limiter"]
    end

    subgraph JobSystem ["Job Queue System"]
        RedisQueue[("Redis Queue (BullMQ)")]
        ScanWorker["Node.js Worker Process"]
    end

    subgraph ScannerEngine ["Scanner Engine (TypeScript)"]
        TargetVal["Target Validator & DNS Resolver"]
        HeadersScan["Security Headers Module"]
        TLSScan["TLS / SSL Module"]
        CookieScan["Cookie Security Module"]
        TechScan["Technology Fingerprinting"]
        DisclosureScan["Info Disclosure Module"]
        InjectionScan["Safe Injection Probe"]
        OWASPEngine["OWASP A01-A10 Mapper"]
        RiskEngine["Risk & Security Score Calculator"]
    end

    subgraph Storage ["Data Layer"]
        MongoDB[("MongoDB Database")]
        RedisCache[("Redis (Pub/Sub & Cache)")]
    end

    subgraph DemoTarget ["Local Security Training Target"]
        VulnerableApp["Controlled Demo App (Flaws for Testing)"]
    end

    UI -->|HTTP / REST| Router
    Router --> AuthMiddleware
    AuthMiddleware --> SSRFGuardian
    SSRFGuardian -->|Enqueues Job| RedisQueue
    RedisQueue --> ScanWorker
    ScanWorker --> ScannerEngine
    ScannerEngine -->|HTTP/TLS Probes| VulnerableApp
    ScannerEngine -->|HTTP/TLS Probes| ExternalTarget["Authorized Target Website"]
    ScannerEngine -->|Store Findings & Results| MongoDB
    ScanWorker -->|Publish Progress| RedisCache
    RedisCache -->|Poll Progress API| UI
    MongoDB --> Router
```

---

## 1. Directory Structure

```
webshield/
├── backend/
│   ├── src/
│   │   ├── controllers/         # Auth, Scan, Report, Dashboard, Admin controllers
│   │   ├── routes/              # Express REST API routes
│   │   ├── middleware/          # Auth JWT, Rate Limit, Validation, Error Handler
│   │   ├── services/            # Database, PDF report generator, Redis queue services
│   │   ├── database/            # MongoDB driver, indexes, initialization & seeds
│   │   ├── scanner/
│   │   │   ├── core/            # TargetValidator, RequestManager, RateLimiter, ScanContext
│   │   │   ├── modules/         # Headers, TLS, Cookie, Tech, Disclosure, Injection, AccessControl
│   │   │   ├── owasp/           # A01 to A10 mapping engines
│   │   │   ├── scoring/         # RiskCalculator, SeverityCalculator
│   │   │   └── reporting/       # Executive summary & detail report generator
│   │   ├── security/            # SSRF protection, IP validation, Sanitization
│   │   └── index.ts             # Server entry point
│   ├── tests/                   # Unit & Integration tests (Jest/Supertest)
│   ├── package.json
│   ├── tsconfig.json
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/          # Gauge, Charts, FindingCard, OWASPBadge, Navbar, Modal
│   │   ├── pages/               # Landing, Dashboard, NewScan, ScanProgress, ScanResults, History, Compare, Admin
│   │   ├── layouts/             # AppLayout, AuthLayout, PublicLayout
│   │   ├── services/            # API client (Axios/Fetch), Auth service, Scan service
│   │   ├── hooks/               # useAuth, useScanProgress, useDashboard
│   │   ├── types/               # TypeScript interfaces (Scan, Finding, OWASP, User)
│   │   └── index.css            # Custom CSS Tokens & Cyber Dark Glassmorphism Styling
│   ├── package.json
│   ├── vite.config.ts
│   └── Dockerfile
├── demo-target/                 # Local Security Training Target container
│   ├── src/                     # Intentionally configurable web server with test vulnerabilities
│   ├── package.json
│   └── Dockerfile
├── docs/                        # Architecture, API, Security Model, Methodology docs
├── docker-compose.yml           # MongoDB, Redis, Backend, Frontend, Demo-Target
├── .env.example
├── .gitignore
└── README.md
```

---

## 2. Core Security & SSRF Guardian Design

To ensure **WebShield** remains safe and defensive:
1. **Target Authorization:** Mandatory user declaration `[x] I confirm that I am authorized to scan this target` verified on both client and backend API payload.
2. **SSRF Guardian Filter (`TargetValidator.ts`):**
   - Parse protocol: restrict strictly to `http:` and `https:`.
   - Resolve hostname via DNS to target IPv4 / IPv6 addresses.
   - Block reserved & private network ranges:
     - `127.0.0.0/8` (Loopback)
     - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private IPv4)
     - `169.254.0.0/16` (Link-local / Cloud Metadata `169.254.169.254`)
     - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 Private/Link-local)
     - Explicit localhost/internal domains unless targeting the specified `DEMO_TARGET_HOST` environment variable explicitly permitted for demo environments.
   - Prevent DNS Rebinding: Re-verify resolved IP before dispatching HTTP socket connections.

---

## 3. Security Scanner & OWASP Engine Modules

| Module Name | Checks & Analysis Conducted | Safety Profile |
| :--- | :--- | :--- |
| **`HeadersScanner`** | Detects missing/misconfigured `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Inspects `Server` & `X-Powered-By` information disclosure. | Passive HTTP GET |
| **`TLSScanner`** | Validates HTTPS availability, HTTP->HTTPS redirect, TLS certificate validity, expiration date, issuer, hostname matching, mixed content indicators. | TLS Socket inspection |
| **`CookieScanner`** | Parses Set-Cookie headers for `HttpOnly`, `Secure`, and `SameSite` flags. Flags insecure session storage. | Passive HTTP Response |
| **`TechnologyScanner`** | Identifies tech stack (React, Express, Nginx, Apache, WordPress, PHP, jQuery, etc.) via header signatures, meta tags, script URLs, known generator tags. | Passive HTML/JS analysis |
| **`InformationDisclosureScanner`** | Probes for exposed `.env.example`, `robots.txt` leaks, exposed `.git/config` paths, stack trace exposures, directory listing status. | Safe HTTP HEAD/GET |
| **`InjectionScanner`** | Tests for reflected query parameter echo, HTML escaping failure indicators, SQL syntax error disclosures. | Non-destructive test strings |
| **`AccessControlScanner`** | Probes common administrative route endpoints (`/admin`, `/config.json`, `/backup.sql`) for open access or directory listing. | Safe HTTP GET probes |
| **`OWASPEngine`** | Maps findings to A01 (Access Control) through A10 (SSRF) categories. Assigns standard status: `PASS`, `FAIL`, `WARNING`, `NOT_TESTED`, `MANUAL_REVIEW_REQUIRED`. | Logic aggregator |
| **`RiskCalculator`** | Computes Security Score starting from 100 with weighted deductions (Critical: -25, High: -15, Medium: -8, Low: -3, Info: -1) and confidence multipliers. | Mathematical Engine |

---

## 4. MongoDB Database Collections & Schema

WebShield uses MongoDB 7.0 as its primary document database. Each collection utilizes UUID string identifiers for cross-collection references and consistency with API contracts.

```json
// 1. users Collection
{
  "_id": ObjectId("..."),
  "id": "d9b939e1-e283-4217-bf45-d88fa7bca001",
  "name": "System Administrator",
  "email": "admin@webshield.io", // Unique Index
  "password_hash": "$2a$10$...",
  "role": "ADMIN", // "USER" | "ADMIN"
  "created_at": "2026-10-25T12:00:00.000Z",
  "updated_at": "2026-10-25T12:00:00.000Z"
}

// 2. scans Collection
{
  "_id": ObjectId("..."),
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "user_id": "d9b939e1-e283-4217-bf45-d88fa7bca001", // Index
  "target_url": "https://example.com",
  "status": "COMPLETED", // "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED"
  "scan_type": "STANDARD", // "QUICK" | "STANDARD" | "DEEP"
  "security_score": 85,
  "coverage_score": 100,
  "started_at": "2026-10-25T12:00:05.000Z",
  "completed_at": "2026-10-25T12:00:45.000Z",
  "created_at": "2026-10-25T12:00:00.000Z" // Index
}

// 3. findings Collection
{
  "_id": ObjectId("..."),
  "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", // Index
  "rule_id": "RULE-SEC-HDR-CSP", // Index
  "title": "Missing Content-Security-Policy (CSP)",
  "description": "The Content-Security-Policy header restricts sources of executable scripts...",
  "severity": "HIGH", // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" (Index)
  "confidence": "HIGH", // "HIGH" | "MEDIUM" | "LOW"
  "status": "CONFIRMED", // "CONFIRMED" | "RESOLVED"
  "owasp_category": "A05",
  "owasp_version": "2025",
  "cwe": "CWE-1021",
  "affected_url": "https://example.com/",
  "evidence": "Response headers did not include 'content-security-policy'",
  "impact": "Increases susceptibility to Cross-Site Scripting (XSS) and data injection.",
  "remediation": "Configure a restrictive Content-Security-Policy HTTP response header.",
  "first_seen_at": "2026-10-25T12:00:00.000Z",
  "last_seen_at": "2026-10-25T12:00:00.000Z",
  "resolved_at": null,
  "created_at": "2026-10-25T12:00:00.000Z"
}

// 4. technologies Collection
{
  "_id": ObjectId("..."),
  "id": "b1a2c3d4-...",
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", // Index
  "name": "Express",
  "version": "4.19.2",
  "category": "Web Framework",
  "confidence": "HIGH"
}

// 5. owasp_results Collection
{
  "_id": ObjectId("..."),
  "id": "e5f6g7h8-...",
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", // Index
  "category": "A05",
  "status": "FAIL", // "PASS" | "FAIL" | "WARNING"
  "score": 70,
  "findings_count": 2
}

// 6. reports Collection
{
  "_id": ObjectId("..."),
  "id": "9a8b7c6d-...",
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", // Index
  "file_path": "/app/temp_reports/WebShield_Report_...pdf",
  "created_at": "2026-10-25T12:01:00.000Z"
}

// 7. audit_logs Collection
{
  "_id": ObjectId("..."),
  "id": "11223344-...",
  "user_id": "d9b939e1-e283-4217-bf45-d88fa7bca001", // Index
  "action": "CREATE_SCAN",
  "metadata": { "scanId": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "targetUrl": "https://example.com" },
  "created_at": "2026-10-25T12:00:00.000Z" // Index
}
```

---

## 5. Development Roadmap & Phased Execution

| Phase | Scope & Key Deliverables |
| :--- | :--- |
| **Phase 1** | Project Setup, Directory Structure, Environment Configuration & Docker Setup |
| **Phase 2** | Database Migrations, Authentication, JWT Security & REST API |
| **Phase 3** | Target Validation, SSRF Protection & Redis Scan Queue |
| **Phase 4** | Node.js Security Scanner Core & OWASP Rule Modules |
| **Phase 5** | Risk Scoring Engine & Detailed Finding Generator |
| **Phase 6** | Local Security Training Target (`demo-target`) Container |
| **Phase 7** | Frontend React Cyber SaaS App & Security Dashboard |
| **Phase 8** | Report Generation, Automated Testing & Documentation |
