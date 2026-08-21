# authforge

# Cloud-Native OAuth2/OIDC Identity Provider — Technical Specification

**Purpose of this document:** This is a complete technical specification for a from-scratch OAuth2/OIDC Identity Provider (IdP). It defines scope, requirements, protocols, data models, infrastructure, security model, and implementation order. It intentionally leaves detailed schema DDL, exact Terraform HCL, and full API contracts for the implementation phase — this document defines *what must be true* about those things, not the final code.

---

## 1. Project Goal and Scope

**Goal:** Build a real, standards-compliant OAuth 2.0 / OpenID Connect Authorization Server (Identity Provider) from scratch — not a demo app that calls Auth0/Cognito, and not a generic SaaS product with authentication bolted on. The IdP *is* the product. It is deployed on AWS using infrastructure-as-code, containerized, and horizontally scalable.

**In scope:**
- A standards-compliant Authorization Server implementing Authorization Code + PKCE and core OIDC.
- Full token lifecycle: access tokens, ID tokens, refresh tokens with rotation and reuse detection.
- Password + TOTP MFA authentication, with account security controls.
- A minimal demo Relying Party (RP) client and a minimal Resource Server (an endpoint protected by the IdP's access tokens) — enough to prove the whole flow end-to-end, not a real product.
- Production-shaped AWS deployment: ECS Fargate, RDS Postgres, ElastiCache Redis, ALB, ECR, Secrets Manager, CloudWatch, provisioned entirely via Terraform.
- CI/CD via GitHub Actions.

**Explicitly out of scope (see §31 for reasoning):**
- Multi-tenancy / organizations.
- Social login / external IdP federation as an input.
- Open/anonymous dynamic client registration (RFC 7591) — clients are registered by an authenticated admin.
- Implicit flow and hybrid flow (deliberately excluded per the OAuth 2.0 Security BCP).
- A full admin dashboard UI — a CLI/seed-script or minimal authenticated admin API is sufficient.
- Multi-region deployment.

---

## 2. Functional Requirements

- Register and manage OAuth clients (confidential and public), each with allow-listed redirect URIs and allowed scopes.
- Authenticate end users via password (Argon2id-hashed) plus optional/required TOTP MFA.
- Execute the OAuth 2.0 Authorization Code flow with mandatory PKCE (S256 only) for all client types.
- Issue RS256-signed JWT access tokens and ID tokens conforming to OIDC Core.
- Issue opaque refresh tokens with rotation on every use and reuse detection.
- Support scope-based authorization and a user consent step.
- Publish a discovery document (`/.well-known/openid-configuration`) and a JWKS endpoint (`/.well-known/jwks.json`).
- Provide a `/userinfo` endpoint that returns claims for a valid access token.
- Support token revocation (RFC 7009) for refresh tokens (and access tokens where feasible).
- Support signing-key rotation without invalidating in-flight tokens.
- Enforce login rate limiting / throttling and record security-relevant audit events.
- Provide a `/health` endpoint suitable for ALB/ECS health checks.

---

## 3. Non-Functional Requirements

- **Statelessness:** the application process must hold no in-memory session or token state; any ECS task can serve any request. All state lives in Postgres or Redis.
- **Horizontal scalability:** the service must run correctly with N ≥ 2 concurrent instances behind a load balancer with no coordination beyond the shared datastores.
- **Security-first:** every design decision in §10–§13 and §22 takes priority over convenience or feature breadth.
- **Reproducibility:** a clean AWS account should be able to reach a running deployment through `terraform apply` plus a CI-built image, with no manual console steps.
- **Observability:** every security-relevant event (defined in §20) must be logged in a form that supports incident investigation without ever logging secrets or raw tokens.
- **Testability:** core protocol logic must be testable without AWS; the whole flow must be testable with Docker Compose locally.
- **Performance targets are measured, not assumed.** Do not invent numbers before the system exists (see §24) — but design for low-milliseconds token issuance under normal load as a working assumption, since this is a stateless, index-backed, cache-assisted service.

---

## 4. Protocols and Specifications to Follow

| Spec | Relevance |
|---|---|
| RFC 6749 — OAuth 2.0 | Core authorization framework |
| RFC 7636 — PKCE | Mandatory for all clients |
| RFC 6750 — Bearer Token Usage | How access tokens are presented to resource servers |
| RFC 7519 — JWT | Access/ID token format |
| RFC 7515 — JWS | JWT signing |
| RFC 7517 — JWK | Key representation for JWKS |
| RFC 8414 — Authorization Server Metadata | `/.well-known/openid-configuration` |
| OpenID Connect Core 1.0 | ID tokens, UserInfo, consent |
| OpenID Connect Discovery 1.0 | Discovery document contents |
| RFC 7009 — Token Revocation | `/revoke` endpoint |
| RFC 6238 — TOTP | MFA |
| OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics) | Justifies excluding implicit/hybrid flow, mandating PKCE everywhere, redirect URI exact-matching |

---

## 5. Recommended Technology Choices and Reasoning

| Layer | Choice | Reasoning |
|---|---|---|
| Language/framework | Python 3.12 + FastAPI | Async, strong typing via Pydantic, auto-generated OpenAPI docs double as living API reference, good fit for a protocol-heavy API. Single primary stack per your requirement. |
| Validation | Pydantic v2 | Already idiomatic with FastAPI; validates request/response shapes including OAuth error responses. |
| ORM/migrations | SQLAlchemy 2.0 (async) + Alembic | Explicit schema control matters here (see §12) — an ORM that stays close to SQL is preferable to a magic query builder. |
| Postgres driver | asyncpg | Fast async driver, plays well with FastAPI's event loop. |
| Redis client | redis-py (asyncio mode) | Official, well-maintained, supports Lua scripting for atomic operations (needed in §13). |
| JWT signing/verification | `pyjwt` or `python-jose`, backed by the `cryptography` library | **Never hand-roll JWS/RSA signing.** These libraries wrap vetted crypto primitives; your own code only orchestrates *when* and *what* to sign, not the cryptographic math itself. |
| Password hashing | `argon2-cffi` (Argon2id) | OWASP-recommended modern password hash; do not use bcrypt/PBKDF2 unless there's a specific constraint. |
| TOTP | `pyotp` | Vetted TOTP implementation; do not hand-roll HMAC-based OTP. |
| Testing | pytest, pytest-asyncio, httpx.AsyncClient | Standard, async-friendly. |
| Load testing | k6 (preferred) or Locust | k6 scripts are easy to run in CI and produce percentile latency output natively. |
| IaC | Terraform, AWS provider | Explicit requirement; also the most portable IaC skill outside AWS-specific tooling like CDK/CloudFormation. |
| Containerization | Docker, multi-stage build | Small, reproducible runtime images. |
| CI/CD | GitHub Actions | Explicit requirement; supports OIDC federation to AWS (no long-lived AWS keys in CI — see §18). |
| Compute | ECS Fargate | See §14 for the explicit reasoning versus EKS/Lambda/EC2. |

**What NOT to use:** Do not use a full OAuth-server framework (e.g., Authlib's `AuthorizationServer`, `django-oauth-toolkit`, or similar) to implement the *protocol orchestration logic* — that would remove the core learning/portfolio value of this project. Vetted libraries are for **primitives** (crypto, hashing, OTP), not for the **protocol decisions** (what to store, when a code is valid, how rotation works) — those are yours to design and implement.

---

## 6. High-Level Architecture

```
                              ┌─────────────────────┐
                              │        Users /       │
                              │   Client Apps (RPs)   │
                              └──────────┬───────────┘
                                         │ HTTPS
                                ┌────────▼─────────┐
                                │   ALB (public)     │
                                │  TLS termination    │
                                └────────┬─────────┘
                     ┌───────────────────┼───────────────────┐
                     │                   │                   │
              ┌──────▼─────┐      ┌──────▼─────┐      ┌──────▼─────┐
              │ ECS Task 1  │      │ ECS Task 2  │      │ ECS Task N  │
              │ FastAPI IdP │      │ FastAPI IdP │      │ FastAPI IdP │
              │ (stateless) │      │ (stateless) │      │ (stateless) │
              └──────┬─────┘      └──────┬─────┘      └──────┬─────┘
                     │                   │                   │
        ┌────────────┼───────────────────┼───────────────────┤
        │            │                   │                   │
 ┌──────▼──────┐          ┌──────────────▼──────────────┐
 │ RDS Postgres │          │      ElastiCache Redis        │
 │  (durable)   │          │  (ephemeral / high-speed)     │
 └─────────────┘          └───────────────────────────────┘

        Secrets Manager  ──▶ signing keys, DB creds, Redis auth
        CloudWatch       ──▶ logs, metrics, alarms
        ECR              ──▶ container images
        Terraform        ──▶ provisions all of the above
```

All application state that must survive a task restart lives in RDS or ElastiCache — never in process memory. Any task can serve any request.

---

## 7. Detailed Component Architecture

**API routers**
- `authorize` — `GET/POST /authorize`
- `token` — `POST /token` (handles `authorization_code` and `refresh_token` grants)
- `revoke` — `POST /revoke`
- `userinfo` — `GET /userinfo`
- `discovery` — `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`
- `auth_ui` — server-rendered `login`, `mfa`, `consent` pages (Jinja2, not a JS framework — see §31)
- `admin` — authenticated client/scope management (CLI-first, minimal API second)
- `health` — `GET /health`, `GET /ready`

**Domain services** (framework-agnostic, unit-testable in isolation)
- `AuthenticationService` — password verification, MFA challenge/verify, login throttling
- `AuthorizationService` — validates `/authorize` requests, redirect URI matching, scope/consent resolution
- `TokenService` — issues/validates access & ID tokens, orchestrates refresh rotation
- `ClientService` — client CRUD, redirect URI and scope validation
- `ConsentService` — records and checks user consent per client/scope
- `KeyManagementService` — current/previous signing keys, JWKS materialization, rotation
- `RateLimitService` — sliding-window / token-bucket limits backed by Redis
- `AuditService` — structured security event emission

**Data access**
- `UserRepository`, `ClientRepository`, `RefreshTokenRepository`, `ConsentRepository`, `SigningKeyRepository` (Postgres)
- `AuthCodeStore`, `SessionStore`, `RateLimitStore` (Redis)

**Cross-cutting middleware**
- Request-ID / correlation-ID injection
- Structured JSON logging with secret redaction
- RFC 6749-compliant OAuth error formatting (`invalid_request`, `invalid_grant`, etc.)
- Rate-limit enforcement

---

## 8. Request/Data Flows for Major OAuth2/OIDC Operations

**A. Authorization Code + PKCE**
1. Client redirects the user's browser to `/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, optional `nonce`.
2. `AuthorizationService` validates `client_id`, exact-matches `redirect_uri` against the client's registered allow-list, and validates requested scopes.
3. If the user has no valid session, they authenticate (password, then MFA if enrolled) via the `auth_ui` router.
4. If consent for this client/scope combination hasn't been recorded, the user is shown a consent screen; `ConsentService` records the decision.
5. `AuthorizationService` generates a single-use authorization code, stores it in Redis (`authz_code:{code}`) with a short TTL (60–120s) holding `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `scope`, `user_id`, `nonce`.
6. Browser is redirected to the client's `redirect_uri` with `code` and `state`.
7. Client's backend calls `POST /token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, and client authentication.
8. `TokenService` atomically fetches-and-deletes the code from Redis (single use, race-safe — see §13), re-validates `redirect_uri` matches exactly, hashes `code_verifier` and compares to the stored `code_challenge` (constant-time compare).
9. On success: issue access token (JWT) and ID token (JWT) via `KeyManagementService`'s current signing key; issue a refresh token (opaque, persisted hashed in Postgres — see §10); return all three per OIDC Core.

**B. Token Refresh (with rotation)**
1. Client calls `/token` with `grant_type=refresh_token` and the refresh token.
2. `TokenService` looks up the token's hash in Postgres inside a transaction with row-level locking.
3. If valid and unused: mark it used, issue a new refresh token in the same token family, issue new access/ID tokens, commit.
4. If already marked used (reuse): treat as a compromise signal — revoke the entire token family, log a `refresh_reuse_detected` audit event, return `invalid_grant`.
5. Concurrent requests presenting the same token are serialized by the DB lock/unique constraint so exactly one succeeds; the other takes the reuse path (see §10 for the exact mechanism).

**C. Revocation** — `POST /revoke` with a refresh token: mark it and its family revoked in Postgres; idempotent; always returns 200 per RFC 7009 regardless of token validity (avoids leaking token validity to unauthenticated callers).

**D. Discovery / JWKS** — static-ish, cacheable responses built from `KeyManagementService` state; JWKS includes all currently-valid public keys (current + any in grace period).

**E. UserInfo** — validates the bearer access token's signature and expiry against JWKS, returns claims scoped to the token's granted scopes.

**F. MFA enrollment** — authenticated user requests a TOTP secret, `pyotp` generates it, user confirms with a live code, service generates and displays one-time recovery codes (stored hashed), `mfa_credentials` row created.

**G. MFA login challenge** — after password success, if the user has MFA enrolled, a short-lived pending-auth session is created and the user must present a valid TOTP code (or a recovery code, single-use) before a full session is issued.

---

## 9. Authentication and Authorization Flows

Keep these conceptually separate:
- **Authentication** = proving *who the user is* (password + MFA), resulting in a browser session.
- **Authorization** = the client asking for *what it may do on the user's behalf* (scopes), resulting in consent + tokens.

**Session handling:** a short-lived server-side session (Redis, `session:{session_id}`) holding `user_id`, `auth_time`, `mfa_verified`, referenced by a `Secure`, `HttpOnly`, `SameSite=Lax` cookie. The cookie is regenerated (new session ID) on privilege change (post-login) to prevent session fixation.

**CSRF protection:** the login and consent forms are the only state-changing, cookie-authenticated, browser-facing endpoints — protect them with a synchronizer token pattern (server-issued token embedded in the form, validated on submit) in addition to `SameSite` cookies.

---

## 10. Token Lifecycle and Refresh-Token Rotation Design

| Token | Format | Lifetime | Storage |
|---|---|---|---|
| Access token | JWT, RS256 | Short (5–15 min) | Not stored — stateless; validated via signature + `exp` |
| ID token | JWT, RS256 | Short, matches access token | Not stored |
| Refresh token | Opaque, 256-bit random, base64url | Longer (days), sliding or absolute — pick one and document it | **Only its SHA-256 hash** stored in Postgres, never the raw value |

**Refresh token table concept:** each row has `token_hash`, `family_id`, `user_id`, `client_id`, `generation`, `previous_token_hash`, `issued_at`, `expires_at`, `used_at` (nullable), `revoked` (bool).

**Rotation rule:** every successful refresh issues a brand-new token in the same `family_id`, and marks the presented token `used_at = now()`. A token can be exchanged exactly once.

**Reuse detection:** if a refresh request presents a token whose `used_at` is already set (or `revoked = true`), this is treated as evidence the token was stolen and replayed — revoke every token in that `family_id`, emit `refresh_reuse_detected`, and require full re-authentication.

**Concurrency / race handling:** two simultaneous requests with the same refresh token must not both succeed. Implement this with a single atomic SQL statement, e.g. `UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL RETURNING *` inside a transaction — only one of the two concurrent requests gets a row back; the other observes zero rows updated and takes the reuse/invalid path. This avoids relying on application-level locking and is safe under Postgres's default read-committed isolation because the `UPDATE ... WHERE used_at IS NULL` is atomic per row.

---

## 11. Signing-Key and JWKS/Key-Rotation Design

- Keys are RSA (2048-bit minimum), generated with the `cryptography` library — never hand-rolled.
- Each key has a `kid` (e.g., ULID or timestamp-prefixed random string) and a `status`: `current`, `retiring`, `retired`.
- Only the `current` key signs new tokens. `current` and `retiring` keys are both published in JWKS so tokens signed moments before a rotation still verify.
- **Storage:** private key material lives only in AWS Secrets Manager (prod) or a local `.env`/encrypted file (dev) — never in Postgres, never in source control. Postgres stores only key **metadata** (`kid`, public JWK, status, timestamps) so the app can build the discovery/JWKS responses without touching Secrets Manager on every request (cache with short TTL instead).
- **Rotation procedure:** generate a new key → mark it `current` → mark the previous `current` as `retiring` (keeps verifying for a grace period ≥ 2× the max access-token TTL) → after the grace period, mark it `retired` and remove from JWKS (private key can then be deleted from Secrets Manager).
- Rotation can be triggered on a schedule (e.g., every 30–90 days) or on-demand (suspected compromise); it should not require redeploying the fleet — running tasks pick up the new `current` key via their periodic metadata refresh.

---

## 12. PostgreSQL Data Model

Postgres is the **source of truth for durable identity/authorization state.** Key tables (columns are illustrative, not final DDL):

| Table | Purpose | Notable constraints/indexes |
|---|---|---|
| `users` | Account identity, hashed password | Unique `email`/`username`; index on `email` |
| `oauth_clients` | Registered clients | Unique `client_id`; `redirect_uris` as a strict allow-list (array or child table) |
| `scopes` | Definable scopes | Unique `name` |
| `client_scopes` | Which scopes a client may request | Composite PK `(client_id, scope_id)` |
| `consents` | User's per-client scope grants | Unique `(user_id, client_id)`; index on `user_id` |
| `refresh_tokens` | Token family/rotation state (§10) | Unique `token_hash`; index on `family_id`, `user_id`; partial index on `used_at IS NULL` for fast active-token lookups |
| `mfa_credentials` | TOTP secret (encrypted at rest), enrollment status | Unique `user_id` (1:1, or 1:N if supporting multiple factors later) |
| `recovery_codes` | Hashed one-time MFA recovery codes | Unique `(user_id, code_hash)`; `used_at` nullable |
| `signing_keys` | Key metadata (§11), not private material | Unique `kid`; index on `status` |
| `audit_log` | Security event log (§20) | Index on `(event_type, created_at)`, `user_id` |

**Transaction boundaries:** refresh-token rotation (§10) and MFA enrollment confirmation must be single atomic transactions. User signup (create user + optionally issue initial session) should also be transactional. Audit log writes should not block or roll back the primary operation — write them in the same transaction where feasible, but design so a logging failure never blocks authentication (see §21 for the trade-off).

---

## 13. Redis Data Model and Use Cases

Redis holds **ephemeral, loss-tolerant, high-speed state**. Nothing whose loss would silently create a security hole should depend solely on Redis surviving — the acceptable failure mode for Redis data loss is "the affected flow has to be retried," never "authorization is bypassed."

| Key pattern | Purpose | TTL | Notes |
|---|---|---|---|
| `authz_code:{code}` | Pending authorization code payload (§8A) | 60–120s | Fetched via an atomic GET+DEL (Lua script or `GETDEL`) so a code can never be redeemed twice even under concurrent requests |
| `session:{session_id}` | Browser login session | Matches cookie TTL | Holds `user_id`, `auth_time`, `mfa_verified` |
| `pending_mfa:{session_id}` | Interim state between password success and MFA success | Short (2–5 min) | Prevents a password-only session from being treated as fully authenticated |
| `ratelimit:login:{key}` | Sliding-window/token-bucket counters, keyed by IP and/or username | Window length | Implemented via `INCR`+`EXPIRE` or a Lua script for atomicity |
| `csrf:{session_id}` | Synchronizer CSRF token | Matches session | |

**Postgres vs. Redis boundary, stated explicitly:** anything that must survive a restart and be auditable later (refresh tokens, consents, users, clients, keys) is Postgres. Anything that is inherently short-lived and safe to lose (auth codes, login sessions, rate-limit counters) is Redis. Do not use Redis as the authority for refresh-token validity — Postgres's atomic `UPDATE ... WHERE used_at IS NULL` (§10) is the actual source of truth; a Redis-based cache in front of it is a pure optimization, never a replacement.

---

## 14. AWS Architecture

**Compute decision — ECS Fargate, with reasoning (not by default):**
- **Vs. EC2:** Fargate removes instance patching/management, which isn't the point of this project — the point is the app and the deploy pipeline, not fleet ops.
- **Vs. Lambda:** a stateful-feeling, low-latency, always-warm authorization endpoint is a poor fit for Lambda's cold-start variance, and modeling long-lived DB/Redis connection pools is more natural in a long-running container.
- **Vs. EKS:** Kubernetes adds a control-plane and operational surface (RBAC, cluster upgrades, ingress controllers) with no architectural benefit for a single-service project — it would be complexity added to lengthen the tech list, which is explicitly against the goal.
- **Conclusion:** ECS Fargate is the right-sized choice for "one containerized, horizontally-scalable, stateless service" without unnecessary operational surface.

**Components:**
- **ALB** (public subnets) — TLS termination (ACM certificate), health checks against `/health`, target group of ECS tasks.
- **ECS Fargate service** (private subnets) — desired task count ≥ 2 for availability; scales via target-tracking (e.g., on CPU or request count per target).
- **RDS Postgres** (private subnets) — Multi-AZ optional depending on budget/goals; parameter group tuned for connection limits appropriate to task count.
- **ElastiCache Redis** (private subnets) — single-node acceptable for portfolio scope; note in the doc that a production system would use a replicated/cluster-mode setup.
- **ECR** — application image repository, immutable tags (git SHA).
- **Secrets Manager** — DB credentials, Redis auth token, current signing-key reference; injected into ECS tasks as task-definition secrets (never baked into the image or committed).
- **CloudWatch** — log group for the ECS task's stdout/stderr (via the `awslogs` driver), custom metrics (EMF or CloudWatch agent) for the business events in §20.
- **IAM** — separate **task execution role** (pull image, write logs, read secrets at launch) from **task role** (runtime AWS API permissions, if any) — least privilege, never one role for both.

---

## 15. Networking and VPC Design

- One VPC, two Availability Zones for baseline resilience.
- **Public subnets** (per AZ): ALB, NAT Gateway.
- **Private subnets** (per AZ): ECS tasks, RDS, ElastiCache — no public IPs anywhere here.
- **Security groups**, each scoped to the minimum required source:
  - `alb-sg`: inbound 443 from `0.0.0.0/0`.
  - `ecs-sg`: inbound on the app port **only** from `alb-sg`.
  - `rds-sg`: inbound 5432 **only** from `ecs-sg`.
  - `redis-sg`: inbound 6379 **only** from `ecs-sg`.
- Route tables: public subnets route `0.0.0.0/0` via the Internet Gateway; private subnets route `0.0.0.0/0` via the NAT Gateway (needed for ECS to pull images/talk to Secrets Manager unless VPC endpoints are used — VPC endpoints for ECR/Secrets Manager/CloudWatch are a reasonable stretch optimization to reduce NAT costs and tighten the network further).

---

## 16. Terraform Structure

Recommended module layout:

```
infra/
  modules/
    vpc/
    ecs/
    rds/
    redis/
    alb/
    ecr/
    secrets/
    iam/
  envs/
    staging/
      main.tf        # wires modules together, small sizing
      terraform.tfvars
    prod/
      main.tf        # same modules, production sizing
      terraform.tfvars
  backend.tf          # S3 backend + DynamoDB lock table
```

- Remote state in S3 with a DynamoDB lock table — required for any team-like or CI-driven workflow to avoid concurrent-apply corruption.
- Image tag (git SHA) is a Terraform variable, so CI/CD can update just that and re-run a targeted apply/deploy without hand-editing infrastructure.
- `staging` and `prod` reuse the same modules with different variable values — never duplicate module logic per environment.

---

## 17. Docker/Container Architecture

- **Multi-stage Dockerfile:** a builder stage installs dependencies (via `uv` or `pip`), a slim final stage (e.g., `python:3.12-slim`) copies only the installed packages and app code.
- Run as a **non-root user**; prefer a read-only root filesystem where the app's own temp/write needs allow it.
- Expose a `/health` endpoint used both by the container `HEALTHCHECK` and the ALB target group.
- Prefer **scaling via ECS task count** over in-process multiple Uvicorn workers — simpler graceful-shutdown semantics and lets ECS's deployment/health-check machinery do the load distribution.
- **Local development:** `docker-compose.yml` with `app` (hot-reload via `uvicorn --reload`, source volume-mounted), `postgres`, `redis`, and optionally a DB inspector (e.g., `pgweb`).

---

## 18. GitHub Actions CI/CD Architecture

Pipeline stages, in order:
1. **Lint/format** (ruff/black) and **type-check** (mypy).
2. **Unit tests** — no external services.
3. **Integration tests** — Postgres and Redis started as GitHub Actions `services:` containers (or via docker-compose), full flow tests run against them.
4. **Build** the Docker image, tag with the git SHA.
5. **Push** to ECR.
6. **`terraform plan`** on pull requests (posted as a PR comment for review); **`terraform apply`** on merge to `main` (staging automatically; production behind a manual approval gate/environment protection rule).
7. **Deploy** — update the ECS task definition's image tag and force a new deployment (ECS's built-in deployment circuit breaker handles automatic rollback on failed health checks).
8. **Smoke test** post-deploy — hit `/health` and `/.well-known/openid-configuration` on the new deployment before considering the pipeline green.

**AWS authentication from CI:** use GitHub Actions' OIDC provider to assume a scoped IAM role (`aws-actions/configure-aws-credentials` with `role-to-assume`) — **no long-lived AWS access keys stored as repo secrets.** This is standard practice regardless of the IdP project itself, but is worth calling out explicitly since it mirrors the OIDC concepts the project itself implements.

---

## 19. Environment, Configuration, and Secrets Strategy

- 12-factor style configuration via environment variables, loaded through a typed Pydantic `Settings` class per environment (`local`, `test`, `staging`, `prod`).
- Local dev: `.env` (gitignored) + `docker-compose.yml`; `.env.example` committed for onboarding.
- Staging/prod: ECS task definition secrets sourced from Secrets Manager (DB URL, Redis URL, signing-key reference, JWT issuer/audience, cookie signing key).
- Never log configuration values that are secrets; log only which config *source* was used (e.g., "loaded DB creds from Secrets Manager") for debuggability.

---

## 20. Observability: Logging, Metrics, Monitoring

**Structured JSON logs**, every entry carrying a request/correlation ID. **Never log raw tokens, passwords, TOTP codes, or refresh-token values** — log identifiers only (`kid`, token `jti`, truncated/hashed refresh-token reference).

**Business/security events to emit** (as both a log line and, where useful, a CloudWatch metric):
`login_success`, `login_failure`, `mfa_challenge_issued`, `mfa_failure`, `token_issued`, `token_refreshed`, `refresh_reuse_detected`, `token_revoked`, `key_rotated`, `authz_failure` (bad redirect URI, invalid client, invalid PKCE, etc.).

**Metrics:** request latency (p50/p95/p99) per route, error rate per route, ECS task CPU/memory, ALB 5xx count and target health, RDS/Redis connection counts.

**Alarms worth defining:** sustained elevated 5xx rate; a spike in `refresh_reuse_detected` (possible token theft in progress); RDS or Redis connection failures; ECS running task count below desired count.

---

## 21. Failure Modes and Recovery Behavior

| Failure | Behavior |
|---|---|
| ECS task crash/restart | Stateless — ALB routes around it once health checks fail; in-flight requests to that task fail and should be retried client-side; no session state is lost because sessions live in Redis, not the process |
| RDS failover (if Multi-AZ) | Brief connection interruption; app's connection pool should reconnect with backoff rather than crash |
| Redis unavailable | **Explicit trade-off to document, not silently pick:** auth-code storage and login sessions are hard dependencies on Redis (their failure legitimately blocks login — acceptable, since it's a genuine availability dependency, not a security one). Rate limiting should default to **fail-open** (don't lock everyone out because the limiter is down) unless the threat model for this deployment specifically prefers fail-closed — state which choice was made and why |
| Signing-key rotation failure mid-rollout | The previous key remains valid through its grace period (§11), so a failed rotation does not invalidate already-issued tokens |
| Deployment failure | ECS deployment circuit breaker automatically rolls back to the last healthy task definition on failed health checks |

---

## 22. Security Threat Model and Mitigations

| Threat | Mitigation | Lives in |
|---|---|---|
| CSRF on login/consent forms | Synchronizer token pattern + `SameSite=Lax/Strict` cookies | Web layer |
| Open redirect / redirect URI manipulation | Exact-match allow-list of registered `redirect_uris`, no wildcard or prefix matching | `ClientService` / `/authorize` |
| Authorization code interception | Mandatory PKCE (S256 only) for every client type, one-time-use codes with short TTL | `/token`, Redis TTL |
| PKCE downgrade | Reject `code_challenge_method=plain`; constant-time comparison of verifier hash | `TokenService` |
| Replay attacks | Nonce in ID tokens, single-use auth codes, short-lived tokens | Multiple layers |
| Refresh token theft/replay | Rotation + family-wide revocation on reuse detection (§10) | `TokenService`/Postgres |
| Token leakage via logs | Tokens/secrets never logged; log redaction middleware | Logging layer |
| Session fixation | Session ID regenerated on privilege escalation (post-login) | `AuthenticationService` |
| Credential stuffing / brute force | Argon2id (slow hash) + per-IP and per-account rate limiting; optional temporary lockout after N failures | `RateLimitService` |
| Secret exposure | Secrets Manager only, least-privilege IAM, nothing in source control or images | Infra |
| Stale/compromised signing key | Scheduled + on-demand rotation with grace-period verification (§11) | `KeyManagementService` |
| Cookie theft | `HttpOnly`, `Secure`, `SameSite` on the session cookie | Web layer |
| SQL injection | Parameterized queries throughout via SQLAlchemy — no string-built SQL | Data layer |
| Over-privileged infra access | Separate ECS task execution vs. task IAM roles; DB/Redis reachable only from the app's security group | Infra |
| Data in transit | ALB terminates TLS via ACM; HTTP→HTTPS redirect enforced | Infra |

---

## 23. Testing Strategy

- **Unit tests:** pure logic with no I/O — PKCE verification, JWT claim construction, password hashing/verification, TOTP verification, rate-limit algorithm.
- **Integration tests:** real Postgres + Redis (docker-compose or testcontainers), full FastAPI `TestClient`/`httpx.AsyncClient` calls.
- **Protocol/flow tests:** complete authorization_code + PKCE round trip; refresh rotation happy path; refresh reuse-detection path; revocation; discovery/JWKS shape validation against the relevant RFCs.
- **Security tests:** invalid PKCE verifier rejected; expired or already-used auth code rejected; mismatched `redirect_uri` rejected; tampered JWT signature rejected; expired token rejected; wrong-audience token rejected.
- **Concurrency test:** fire two simultaneous refresh requests with the same token and assert exactly one succeeds while the other triggers the reuse path (§10) — this is one of the most important tests in the whole project.
- **Database tests:** constraint/uniqueness enforcement, Alembic migration up/down correctness.
- **Redis tests:** TTL expiry behavior, atomicity of the auth-code get-and-delete.
- **Failure/recovery tests:** simulate Redis and Postgres being unreachable and assert the documented behavior in §21 actually happens.
- Aim for strong coverage (e.g., 80%+) concentrated on token/auth logic rather than a blanket number across the whole codebase.

---

## 24. Load-Testing Strategy

Use k6 (or Locust) against a **deployed staging environment**, not just localhost — numbers from a laptop don't reflect ECS/RDS/ElastiCache reality.

Scenarios:
- Authorization-code-for-token exchange throughput.
- Refresh endpoint under concurrent load — this must validate *correctness* (rotation/reuse detection holding up under load), not just latency.
- Login endpoint under load with rate limiting actively engaged.

Metrics to capture once the system exists (do not pre-invent numbers): sustained requests/sec, p50/p95/p99 latency, error rate, ECS task CPU/memory under load, the DB connection-pool saturation point, and observed behavior when ECS autoscaling triggers.

---

## 25. Local Development Architecture

- `docker-compose.yml`: `app` (hot reload, source volume-mounted), `postgres`, `redis`, optional `pgweb` for inspection.
- `.env.example` committed; `.env` gitignored.
- A `Makefile` (or `justfile`) exposing `make up`, `make down`, `make migrate`, `make test`, `make lint` as the standard entry points so the whole dev loop is a handful of memorable commands.
- Alembic migrations run explicitly (`make migrate`), not silently on every app boot, to keep schema changes visible and intentional.

---

## 26. Deployment Architecture

**Environments:** local → CI test environment (ephemeral, spun up per PR via docker-compose in GitHub Actions) → staging (persistent AWS environment, small instance sizes) → production-like (same Terraform modules, larger sizing, Multi-AZ RDS if budget allows).

**Deploy flow:** GitHub Actions builds an image tagged with the git SHA → pushes to ECR → `terraform apply`/`aws ecs update-service` references the new tag → ECS performs a rolling deployment with the deployment circuit breaker enabled (auto-rollback on failed health checks) → a post-deploy smoke test hits `/health` and `/.well-known/openid-configuration` before the pipeline is considered successful.

### Staging bootstrap checklist (manual / first bring-up)

RDS and Redis stay private (reachable only from `ecs-sg`). Do **not** open them to the internet and do **not** rely on a bastion — run admin work as one-off Fargate tasks on the same task definition, private subnets, and security group as the service (`scripts/run-ecs-oneoff.sh`, wrapped by the Make targets below).

1. **Apply staging infra** (once): `terraform -chdir=infra/envs/staging apply`
2. **Build and push an image** to ECR (immutable tags; prefer the git SHA, or a one-off tag like `v1` for a manual first push).
3. **Point ECS at that image** and roll the service:
   ```bash
   terraform -chdir=infra/envs/staging apply -var='image_tag=v1'
   ```
   (`image_tag` defaults to `latest` in `infra/envs/staging/variables.tf` if unset in `terraform.tfvars`.)
4. **Confirm tasks are healthy** — CloudWatch log group `/ecs/authforge-staging`; ALB target-group health `healthy`; `aws ecs describe-tasks` shows `lastStatus=RUNNING` / `desiredStatus=RUNNING` (not a tight stop/start loop with a non-zero `containers[].exitCode`).
5. **Migrate schema, then create the first signing key** (order matters — the `signing_keys` table must exist first):
   ```bash
   make migrate-staging
   make bootstrap-keys-staging
   ```
   On a brand-new environment run **`authforge-admin keys init`** (what `make bootstrap-keys-staging` calls). Prefer `keys init` / `keys bootstrap` over `keys rotate` for the first key: `rotate` works with zero keys, but a second rotate would demote the first key to `retiring`.

One-off tasks reuse the service task definition with a `command` override via `aws ecs run-task`; cluster / task definition / subnets / security group / log group come from `terraform output`, not hardcoded values.

After the first bring-up, day-to-day staging deploys go through GitHub Actions on `main` (build → push → terraform apply → smoke), not manual `docker push` / `terraform apply` unless you are recovering from a failed run.

---

## 27. Recommended Repository Structure

```
.
├── app/
│   ├── api/                 # FastAPI routers (authorize, token, revoke, userinfo, discovery, auth_ui, admin, health)
│   ├── services/             # AuthenticationService, AuthorizationService, TokenService, ClientService,
│   │                          # ConsentService, KeyManagementService, RateLimitService, AuditService
│   ├── repositories/          # Postgres repositories
│   ├── stores/                 # Redis-backed stores (auth codes, sessions, rate limits)
│   ├── models/                  # SQLAlchemy models
│   ├── schemas/                  # Pydantic request/response schemas
│   ├── templates/                 # Jinja2 login/consent/MFA pages
│   ├── config.py
│   └── main.py
├── migrations/                # Alembic
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
├── infra/                    # Terraform (see §16)
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── .github/workflows/
│   └── ci-cd.yml
├── loadtest/                 # k6 scripts
├── .env.example
├── Makefile
└── README.md
```

---

## 28. Implementation Phases

| Phase | Goal | Key deliverables | Exit criteria (must be true before moving on) |
|---|---|---|---|
| **1** | Core protocol logic, local only | `AuthorizationService`, `TokenService` skeleton, PKCE/JWT logic, in-memory or SQLite stand-ins | Unit tests pass for PKCE verification, JWT construction/verification, no DB yet required |
| **2** | Full flow with real Postgres + Redis | All repositories/stores wired to real Postgres/Redis via docker-compose; complete `/authorize` → `/token` → `/userinfo` round trip; refresh rotation + reuse detection implemented | A full authorization_code+PKCE flow and a refresh rotation flow both work end-to-end locally, including the concurrency test from §23 |
| **3** | Security hardening + comprehensive tests | Rate limiting, MFA (TOTP + recovery codes), Argon2id, CSRF/session hardening, the full security test suite from §23 | Every mitigation in §22's table has at least one passing test exercising it |
| **4** | Containerization | Multi-stage Dockerfile, docker-compose parity with "local dev" | `docker compose up` reproduces the full working system from a clean checkout |
| **5** | AWS infrastructure via Terraform | VPC, RDS, ElastiCache, ECR, Secrets Manager, IAM modules | `terraform apply` in a clean AWS account provisions all infra with no manual console steps (ECS service can still be at zero tasks) |
| **6** | Deployment to ECS/Fargate | ALB + ECS service modules, task definition wired to Secrets Manager | The app is reachable over HTTPS through the ALB, running as ≥2 Fargate tasks, talking to RDS/Redis in private subnets |
| **7** | CI/CD | GitHub Actions pipeline (lint/test/build/push/plan/apply/deploy/smoke-test), GitHub OIDC → AWS IAM role | A merge to `main` deploys to staging with no manual steps; PRs get a `terraform plan` comment |
| **8** | Observability, load testing, failure testing, final hardening | CloudWatch metrics/alarms, k6 load-test scripts run against staging, chaos-style failure tests (kill a task, block Redis) | Alarms exist for the events in §20; load test produces real p95/error-rate numbers; documented failure modes from §21 are verified, not just assumed |

Do not blend phases — e.g., do not start Terraform (Phase 5) before the refresh-rotation concurrency test (Phase 2/3) is green. The point of this ordering is to avoid ending up with a half-working auth core and a half-working AWS footprint at the same time.

---

## 29. Build-From-Scratch vs. Libraries vs. Never-Reinvent

| Category | Examples | Why |
|---|---|---|
| **Implement yourself** | Authorization Code + PKCE orchestration, consent logic, refresh rotation/reuse-detection state machine, discovery/JWKS response assembly, rate-limit policy, audit event design | This *is* the point of the project — protocol and security **decisions**, not just calling a library that already made them |
| **Use a vetted library, own the integration** | JWT signing/verification (`pyjwt`/`python-jose` + `cryptography`), password hashing (`argon2-cffi`), TOTP (`pyotp`), DB driver/ORM, Redis client | These wrap correctness-critical primitives that are easy to get subtly wrong; using them is the professional choice, not a shortcut |
| **Never reinvent, ever** | RSA/AES implementations, hash function internals, random number generation (`secrets`, not `random`), TLS itself | Cryptographic primitives are exactly where "not invented here" causes real vulnerabilities |
| **Do not use a full OAuth-server framework** | Authlib's `AuthorizationServer`, `django-oauth-toolkit`, Ory Hydra as a library | Would remove the protocol-orchestration learning value that is the entire premise of the project |

---

## 30. Essential vs. Optional Scope

**Essential (defines "done" for the core project):**
Authorization Code + PKCE, RS256 JWTs with JWKS and key rotation, refresh rotation with reuse detection, Argon2id password auth, TOTP MFA with recovery codes, the Postgres/Redis split as designed in §12–13, Docker, AWS deployment via Terraform (VPC, ECS Fargate, RDS, ElastiCache, ALB, ECR, Secrets Manager), a working GitHub Actions pipeline (test → build → push → deploy to staging), the core security test suite (§22/§23), and basic CloudWatch logging.

**Optional / stretch extensions (valuable, but not required for the project to be "complete"):**
- Production environment with manual-approval CD gate (staging-only CI/CD satisfies the core requirement).
- Registering the IdP itself as a federated OIDC identity source trusted by AWS IAM (the "optional advanced cloud integration" from the brief) — a genuinely nice capstone proving real-world OIDC compliance, but adds an AWS IAM trust-policy surface that's tangential to the IdP's own correctness.
- k6 load-testing wired into CI (rather than run manually/ad hoc).
- CloudWatch dashboards beyond baseline alarms.
- `client_credentials` grant for machine-to-machine access.
- Admin web UI (vs. CLI/seed script).
- Blue/green or canary deployments (ECS's rolling deployment + circuit breaker already covers safe deploys adequately for this scope).

---

## 31. Complexity Guardrails and Key Trade-offs

- **No frontend framework.** Server-rendered Jinja2 pages for login/consent/MFA are sufficient and keep the project's scope on backend/security/cloud — which is the stated goal — rather than on frontend engineering.
- **No open dynamic client registration.** Clients are created by an authenticated admin (CLI or minimal authenticated endpoint), which avoids an entire class of abuse surface (anonymous client registration flooding/spoofing) that RFC 7591 support would introduce, without weakening the project's OAuth-server credibility.
- **Implicit and hybrid flows are deliberately excluded**, matching current OAuth Security BCP guidance — implementing a flow that's officially discouraged would be effort spent away from doing Authorization Code + PKCE really well.
- **Single AWS region.** Multi-region adds data-replication and failover complexity disproportionate to the portfolio goal.
- **Single-node ElastiCache is acceptable for this project's scope** — note the production-grade alternative (replication group / cluster mode) in documentation rather than building it, so the trade-off is explicit rather than silently absent.
- **Don't chase OIDC feature-completeness.** Skip pairwise subject identifiers, request objects (JAR/JARM), and less-common optional OIDC features — implement the core flow correctly and deeply rather than the full spec shallowly. This directly serves the stated priority: "technical depth, correctness, interviewability, and genuine engineering value... not the largest possible technology stack."
