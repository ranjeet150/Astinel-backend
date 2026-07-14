# Astinel Backend — Engineering Issues

> Generated from full-source audit

## Contents

1. [Auth & State Management](#1-backend-auth--state-management)
2. [API & Routes](#2-backend-api--routes)
3. [Scanner & Analysis](#3-backend-scanner--analysis)
4. [Database & Storage](#4-backend-database--storage)
5. [Integration & Contracts](#5-backend-integration--contracts)
6. [Testing & Quality](#6-backend-testing--quality)
7. [Security](#7-backend-security)
8. [Developer Experience](#8-backend-developer-experience)

---

# 1. Backend: Auth & State Management

## Issue #1 — `auth_middleware` applies to all routes including public endpoints

**Labels:** backend, bug, security, api

**Summary:**
`src/api/mod.rs:34-37` applies the `auth_middleware` as a layer on every route. The middleware in `src/api/middleware.rs:82-91` silently falls back to `AuthContext::anonymous()` when no token is present. This means: (1) public endpoints (`/v1/health`, `/v1/version`, `/metrics`, `/v1/openapi.json`) still run through auth processing, wasting CPU and creating potential for future auth errors; (2) anyone hitting the middleware with an invalid token still gets `AuthContext::anonymous()` — the error is silently swallowed.

**Acceptance Criteria:**

- [ ] Move public routes to a separate router that does not include the auth layer
- [ ] Or update the middleware to skip processing for known public paths
- [ ] Add a test verifying that public endpoints return 200 without any auth header

**Difficulty:** Intermediate

## Issue #2 — Refresh endpoint does not invalidate old refresh token

**Labels:** backend, bug, auth

**Summary:**
`src/api/routes/auth.rs:148-163`: The `refresh` endpoint validates the old refresh token and issues a new token pair, but never invalidates the old refresh token in Redis. A leaked refresh token can be used repeatedly to obtain new access tokens until it expires naturally (30 days by default).

**Acceptance Criteria:**

- [ ] Delete the old refresh token from the `SessionStore` before issuing new tokens
- [ ] Store the new refresh token's `jti` in Redis after issuance
- [ ] Add a test that verifies refresh tokens cannot be reused

**Difficulty:** Intermediate

## Issue #3 — Wallet login creates users with placeholder email and generic role

**Labels:** backend, bug, auth

**Summary:**
`src/api/routes/wallet.rs:74` creates users with `email = format!("wallet-{}@astinel.io", ...)` — a non-deliverable placeholder. These users can never reset passwords or receive notifications. Line 119 issues tokens with hardcoded `"wallet@astinel.io"` email and `"user"` role instead of the actual user record values.

**Acceptance Criteria:**

- [ ] Use the user's actual email from the database record when issuing tokens
- [ ] Mark wallet-created users with an `auth_method` or require email verification
- [ ] Use the user's stored role from the database rather than hardcoding `"user"`

**Difficulty:** Intermediate

## Issue #4 — Wallet login does not send refresh token to SessionStore

**Labels:** backend, bug, auth

**Summary:**
`src/api/routes/auth.rs:42-45` calls `state.jwt_service.issue_tokens(...)` but never stores the refresh token's `jti` in Redis via `session_store.store_refresh_token()`. This means refresh tokens issued through the login endpoint are never tracked and cannot be individually revoked. The same issue applies to the register endpoint (`line 111-119`) and the wallet login endpoint (`line 117-120`).

**Acceptance Criteria:**

- [ ] After `issue_tokens()`, call `session_store.store_refresh_token(jti, ttl_secs)` in all three auth endpoints
- [ ] Store the JTI from the refresh claims, not the access claims
- [ ] Add integration test verifying token revocation

**Difficulty:** Intermediate

## Issue #5 — `api_key_repository.update_last_used` error silently ignored in middleware

**Labels:** backend, bug, api

**Summary:**
`src/api/middleware.rs:48`: `let _ = state.api_key_repository.update_last_used(api_key.id).await;` discards the error with `let _`. If the database write fails (e.g., transient network error), the API key usage tracking silently breaks, but the request is still permitted.

**Acceptance Criteria:**

- [ ] Log the error with `tracing::warn!` instead of discarding
- [ ] Consider degrading gracefully (permit the request, log the failure)
- [ ] Add a test verifying graceful degradation

**Difficulty:** Beginner

## Issue #6 — JWT validation uses default Validation which does not check issuer or audience

**Labels:** backend, bug, security, auth

**Summary:**
`src/auth/jwt.rs:102`: `Validation::default()` only validates expiry (`exp`) and signature. It does not validate `iss` (issuer), `aud` (audience), or `nbf` (not before). If a JWT from another service using the same secret were presented, it would be accepted.

**Acceptance Criteria:**

- [ ] Add issuer validation to match the expected `iss` claim
- [ ] Consider adding an audience claim for the specific service
- [ ] Set a leeway of 60 seconds for clock skew

**Difficulty:** Intermediate

## Issue #7 — RateLimiter is never called from any route or middleware

**Labels:** backend, feature, security

**Summary:**
`src/cache/redis.rs:50-99` defines a complete `RateLimiter` with sliding-window ZSET-based rate limiting. However, no route handler, middleware, or service calls `rate_limiter.check_rate_limit()`. The rate limiter is instantiated in `AppState` (`src/state/mod.rs:55`) but remains dead code.

**Acceptance Criteria:**

- [ ] Add rate-limiting middleware that calls `rate_limiter.check_rate_limit()` per-user or per-IP
- [ ] Configure per-endpoint rate limits (e.g., 10 req/s for scans, 30 req/s for reads)
- [ ] Add `X-RateLimit-Remaining` and `Retry-After` headers to responses
- [ ] Return 429 Too Many Requests when limit is exceeded

**Difficulty:** Advanced

## Issue #8 — Missing logout endpoint

**Labels:** backend, feature, api, auth

**Summary:**
The API spec in `API.md:41` documents `POST /v1/auth/logout` with `{ refresh_token }` → `{ success: true }`. However, `src/api/routes/auth.rs:165-170` only registers `/login`, `/register`, and `/refresh`. The logout endpoint is completely missing — no route, no handler.

**Acceptance Criteria:**

- [ ] Implement `POST /v1/auth/logout` that accepts a refresh token
- [ ] Call `session_store.invalidate_refresh_token(jti)` with the token's JTI
- [ ] Register the route in the auth router
- [ ] Add test verifying token cannot be reused after logout

**Difficulty:** Intermediate

## Issue #9 — No input validation on user registration fields

**Labels:** backend, enhancement, security

**Summary:**
`src/api/routes/auth.rs:54-58` and `wallet.rs:36-38`: Registration accepts arbitrary strings for `email`, `password`, and `display_name` with no validation. There is no check for email format validity, password minimum length or complexity, or display name length or character restrictions.

**Acceptance Criteria:**

- [ ] Add email format validation (regex or validator crate)
- [ ] Enforce minimum password length (12 characters, at least one uppercase, one digit)
- [ ] Truncate or reject overly long display names (>50 chars)
- [ ] Return 400 with structured error details on validation failure

**Difficulty:** Beginner

## Issue #10 — Refresh token has 30-day TTL with no forced rotation

**Labels:** backend, security, auth

**Summary:**
`src/auth/jwt.rs:37`: Refresh tokens are valid for 30 days by default. There is no maximum token age, no forced re-authentication after a configurable period, and no revocation endpoint. A stolen refresh token gives an attacker access for up to 30 days.

**Acceptance Criteria:**

- [ ] Add max session duration (e.g., 7 days absolute, 30 minutes of inactivity)
- [ ] Implement token rotation with immediate old-token invalidation
- [ ] Add a `/v1/auth/revoke-all` endpoint that invalidates all sessions for a user

**Difficulty:** Intermediate

## Issue #11 — API key authentication maps to hardcoded "developer" role

**Labels:** backend, security, auth

**Summary:**
`src/api/middleware.rs:40`: API key authenticated requests are given `Role::Developer` regardless of the key's actual configured role in the database. The `ApiKey` model has a `role` or `permissions` field that is ignored during authentication.

**Acceptance Criteria:**

- [ ] Read the actual role/permissions from the `ApiKey` database record
- [ ] Map database role to the `AuthContext` role
- [ ] Add a migration if the `api_keys` table does not store role information

**Difficulty:** Intermediate

---

# 2. Backend: API & Routes

## Issue #12 — `list_scans` passes `org_id` where `project_id` is expected

**Labels:** backend, bug, api

**Summary:**
`src/api/routes/scans.rs:81` calls `state.scan_repository.list_jobs_for_project(org_id)` but the parameter name and the repository signature suggest this should be a `project_id`, not an `org_id`. The query likely joins through `projects` table to filter by organization, but the name is misleading and suggests a logic error if `list_jobs_for_project` expects a project UUID but receives an organization UUID.

**Acceptance Criteria:**

- [ ] Audit the `list_jobs_for_project` implementation to confirm it correctly filters by organization
- [ ] Rename the repository method to `list_jobs_for_organization` or add a separate method
- [ ] Add a test that verifies scan isolation between different organizations

**Difficulty:** Intermediate

## Issue #13 — Dashboard does not scope scans by organization for `recent_scans` query

**Labels:** backend, bug, api, data-leakage

**Summary:**
`src/api/routes/dashboard.rs:120-131`: The `recent_scans` query joins `scan_jobs` → `projects` and filters by `p.organization_id = $1`. This is correct. However, if `org_id` is `Uuid::nil()` (the fallback when `auth.org_id` is None), all queries will match rows where `organization_id` is the nil UUID — which should be zero rows, but could also match any unset org_id, potentially leaking cross-organization data if a bug exists elsewhere.

**Acceptance Criteria:**

- [ ] Reject the request with 400 if `auth.org_id` is None (no org context)
- [ ] Add a test that verifies organization data isolation

**Difficulty:** Intermediate

## Issue #14 — `list_scans` returns raw JSON without `ApiResponse` wrapper

**Labels:** backend, bug, api

**Summary:**
`src/api/routes/scans.rs:109` returns `Ok(Json(resp))` directly instead of `Ok(ApiResponse::ok(...))`. All other endpoints wrap responses in `ApiResponse { success: true, data: ... }` but `list_scans` returns a bare array. This breaks API consistency for clients that expect the wrapper.

**Acceptance Criteria:**

- [ ] Wrap `list_scans` response in `ApiResponse::ok()`
- [ ] Add a test comparing the response shape across all list endpoints

**Difficulty:** Beginner

## Issue #15 — No project-level settings API

**Labels:** backend, feature, api

**Summary:**
The `Project` model has a `settings` field (`serde_json::Value`), but there is no API endpoint to read or update project-level settings. Settings like default branch, scan configuration overrides, notification preferences, and webhook URLs are stored but inaccessible.

**Acceptance Criteria:**

- [ ] Add `GET /v1/projects/{id}/settings` and `PUT /v1/projects/{id}/settings` endpoints
- [ ] Define a schema for known settings fields
- [ ] Validate settings against the schema on update

**Difficulty:** Intermediate

## Issue #16 — Pagination for list endpoints is defined but not enforced

**Labels:** backend, enhancement, api, performance

**Summary:**
`FindingsQuery` in `src/api/routes/findings.rs:17-24` accepts `page` and `per_page` parameters, but they are never passed to the repository — `list_by_scan_result` always returns all results. The `list_projects`, `list_scans`, and `list_contracts` endpoints have no pagination parameters at all.

**Acceptance Criteria:**

- [ ] Add `LIMIT`/`OFFSET` to all repository list methods
- [ ] Return `PaginatedResponse<T>` instead of `Vec<T>` where pagination is accepted
- [ ] Default `per_page` to 50, max 200
- [ ] Add tests for pagination behavior

**Difficulty:** Intermediate

## Issue #17 — Finding list ignores query filters `severity`, `category`, `file_path`

**Labels:** backend, enhancement, api, bug

**Summary:**
`src/api/routes/findings.rs:56-64`: The `list_findings` handler reads `scan_id` from the query, then calls `finding_repository.list_by_scan_result()` which does not apply any of the `severity`, `category`, or `file_path` filters. A separate method `list_with_filters` exists on the repository but is never called by this handler.

**Acceptance Criteria:**

- [ ] Call `list_with_filters` instead of `list_by_scan_result` when any filter is present
- [ ] Validate filter enum values before querying
- [ ] Add tests for each filter combination

**Difficulty:** Intermediate

## Issue #18 — Scan trigger endpoint uses `serde_json::Value` instead of typed request

**Labels:** backend, enhancement, api

**Summary:**
`src/api/routes/scans.rs:39` uses `Json(req): Json<serde_json::Value>` instead of a strongly typed `#[derive(Deserialize)] struct`. Fields like `project_id`, `branch`, and `config` are extracted with `.get("field_name")` string lookups. This loses compile-time type safety, auto-generated OpenAPI schema, and IDE support.

**Acceptance Criteria:**

- [ ] Define a `TriggerScanRequest` struct with typed fields
- [ ] Add validation for required fields (project_id)
- [ ] Generate proper OpenAPI schema from the struct

**Difficulty:** Intermediate

## Issue #19 — Error responses use inconsistent code format

**Labels:** backend, enhancement, api

**Summary:**
`src/api/errors.rs:36-37`: Error responses return `"code": status.as_u16()` — the HTTP status code as an integer. This mixes the HTTP layer with the application error model. Clients cannot distinguish between "Not found: project" and "Not found: scan" without parsing the `message` string, which is fragile.

**Acceptance Criteria:**

- [ ] Replace numeric codes with application-specific error codes (e.g., `"PROJECT_NOT_FOUND"`, `"SCAN_NOT_FOUND"`)
- [ ] Add optional `details` field for validation errors
- [ ] Document all error codes in API.md

**Difficulty:** Beginner

## Issue #20 — Scan result response includes all findings in one payload

**Labels:** backend, enhancement, api, performance

**Summary:**
`/v1/scans/{id}/results` returns the `ScanResult` metadata but does not include the actual findings. Clients must make a separate call to `/v1/findings?scan_id={id}`. For scans with hundreds of findings, the findings endpoint returns everything without pagination, causing large JSON payloads.

**Acceptance Criteria:**

- [ ] Include paginated findings inline in the scan result response with `?include_findings=true`
- [ ] Default findings to paginated (page 1, per_page 50) when included
- [ ] Add `total_findings` to the scan result response for UI pagination

**Difficulty:** Intermediate

## Issue #21 — N+1 query in `list_scans` for score and progress

**Labels:** backend, performance, api

**Summary:**
`src/api/routes/scans.rs:73-110`: For each scan job, the handler makes two additional queries: (1) `find_result_by_job(job.id)` — a database query per scan, (2) `scan_status_cache.get_progress(...)` — a Redis call per scan. With 100 scans, this becomes 1 (list) + 100 (results) + 100 (progress) = 201 round trips.

**Acceptance Criteria:**

- [ ] Eager-load the scan result data with a JOIN in the list query
- [ ] Batch the Redis progress lookups with a single MGET command
- [ ] Remove the N+1 by including result data in the initial job query

**Difficulty:** Advanced

## Issue #22 — Unbounded result sets in all list endpoints

**Labels:** backend, performance, api

**Summary:**
`list_scans`, `list_findings`, `list_projects`, `list_contracts`, `list_reports`, and `list_notifications` all return every matching row from the database with no LIMIT clause. A project with 10,000 scans will return 10,000 records in a single response, consuming unbounded memory on both the server and client.

**Acceptance Criteria:**

- [ ] Add a default LIMIT of 50 to all list queries
- [ ] Implement cursor-based or offset-based pagination
- [ ] Return a `PaginatedResponse` with `total`, `page`, `per_page`
- [ ] Document the pagination behavior

**Difficulty:** Intermediate

---

# 3. Backend: Scanner & Analysis

## Issue #23 — `parse_contract` test helper panics with `unimplemented!()`

**Labels:** backend, bug, scanner

**Summary:**
`src/scanner/parser/ast.rs:406` contains `unimplemented!("full parser not yet implemented; use build_ functions in tests")`. The module comment at line 404 says "TODO: Phase 3+ will implement full syn-based parsing." Any code path that calls `test_helpers::parse_contract()` will panic at runtime. Since `DefaultScanner::scan()` does not call this function, the production pipeline works, but the lack of a text-to-AST pipeline means rule tests cannot validate against real source code — only manually constructed ASTs.

**Acceptance Criteria:**

- [ ] Implement `parse_contract(source: &str) -> ParsedProject` using the existing `syn`-based logic in `parser_impl.rs`
- [ ] Remove the `unimplemented!()` macro
- [ ] Add integration tests that parse real Soroban contract source files
- [ ] Deprecate or keep the `build_*` helpers for edge-case testing

**Difficulty:** Advanced

## Issue #24 — `scan_job` executor ignores queued job config

**Labels:** backend, bug, jobs

**Summary:**
`src/jobs/scan_job.rs:58` passes only the target path when building `ScanRequest`, discarding `job.config` entirely. Any scan configuration that was provided when the job was enqueued (e.g., `ScanType`, severity filter, enabled rules) is lost, and the scan always runs with default settings.

**Acceptance Criteria:**

- [ ] Deserialize the `config` field from the `QueuedJob` into the `ScanRequest`
- [ ] Map `ScanType`, severity filters, rule overrides, and AI flag from config
- [ ] Add a test that verifies config propagation through enqueue → execute

**Difficulty:** Intermediate

## Issue #25 — `scan_job` `error_message` not preserved on scan failure in executor

**Labels:** backend, bug, jobs

**Summary:**
`src/jobs/scan_job.rs:63-68`: When a scan fails, `error_message` is set on the DB job record. However, the `ScanResult` model (`src/database/models/scan_result.rs`) has no `error_message` field, so the failure details are only on the job — the scan result won't reflect why it failed. The API endpoint `/v1/scans/{id}/result` returns the `ScanResult`, not the job, so clients never see the error.

**Acceptance Criteria:**

- [ ] Add an `error_message` field to the `ScanResult` model and migration
- [ ] Set it when the scan fails in the executor
- [ ] Include `error_message` in the `/v1/scans/{id}/result` response

**Difficulty:** Intermediate

## Issue #26 — Scan queue has no priority scheduling

**Labels:** backend, feature, jobs

**Summary:**
`src/jobs/queue.rs` uses Redis `LPUSH`/`BRPOP` which implements a simple FIFO queue. The `ScanJob.priority` field (i32) exists in the database and model but is never read by the queue. All jobs are treated with equal priority regardless of the `priority` value.

**Acceptance Criteria:**

- [ ] Replace the simple list with a Redis sorted set (ZADD/ZRANGEBYSCORE) keyed by priority
- [ ] Or maintain separate queues for different priority tiers
- [ ] Ensure high-priority scans (e.g., GitHub PR checks) are processed before batch scans

**Difficulty:** Advanced

## Issue #27 — No scan cancellation signal propagation to worker

**Labels:** backend, feature, jobs

**Summary:**
`src/api/routes/scans.rs:153-184`: The `cancel_scan` endpoint updates the database status to `cancelled` and marks the job in the `ScanStatusCache`. However, if a worker has already dequeued the job and is running it, there is no mechanism to signal the in-flight execution to stop. The scan continues running until completion, at which point the (now-cancelled) job gets a completed status anyway.

**Acceptance Criteria:**

- [ ] Add a cancellation channel (e.g., `tokio::sync::watch` or Redis pub/sub) per job
- [ ] Check the cancellation flag periodically during scan execution
- [ ] If cancelled mid-scan, return partial results or mark as cancelled-with-partial-data

**Difficulty:** Advanced

## Issue #28 — `RuleEngine` and `RuleRunner` are duplicate implementations

**Labels:** backend, refactor, code-quality

**Summary:**
`src/scanner/rules/mod.rs:23-84` defines `RuleEngine` with its own `run()` method, and `src/scanner/rules/runner.rs:10-77` defines `RuleRunner` with an identical `run()` method. Both take the same inputs (`RuleRegistry`, `RuleConfig`, optional `SuppressionEngine`), iterate over filtered rules, collect findings, apply suppression, and return `RuleResult`. One should delegate to the other or be removed entirely.

**Acceptance Criteria:**

- [ ] Remove `RuleRunner` and delegate all callers to `RuleEngine`
- [ ] Or vice versa — keep the one with more features
- [ ] Update all references in `scanner/mod.rs` and test files

**Difficulty:** Intermediate

## Issue #29 — `scanner/mod.rs` uses `execute_rules` that wraps `RuleEngine` unnecessarily

**Labels:** backend, refactor, code-quality

**Summary:**
`src/scanner/mod.rs:160-184`: The `execute_rules` function creates a `SuppressionEngine` from source files, constructs a `RuleEngine`, calls `run()`, and extracts the results. This indirection is no longer necessary since `DefaultScanner::scan()` calls it directly. The logic could be inlined.

**Acceptance Criteria:**

- [ ] Inline `execute_rules` into `DefaultScanner::scan()`
- [ ] Or move it to a method on `DefaultScanner`

**Difficulty:** Beginner

## Issue #30 — Cross-contract call analysis not tracked through visitor

**Labels:** backend, refactor, scanner

**Summary:**
The `AstVisitor` trait in `src/scanner/parser/visitor.rs:7-29` provides visitor methods for most AST node types but omits `visit_cross_contract_call` and `visit_deployer_call`. The `walk_function` helper also omits iterating over `body.cross_contract_calls` and `body.deployer_calls`. This means rule implementations using the visitor pattern cannot detect cross-contract call issues or deployer call issues without manual pattern matching.

**Acceptance Criteria:**

- [ ] Add `visit_cross_contract_call` and `visit_deployer_call` to the `AstVisitor` trait
- [ ] Update `walk_function` to iterate over both collections
- [ ] Add a test that verifies the visitor visits all node types

**Difficulty:** Intermediate

## Issue #31 — Blocking `std::fs` calls in async context

**Labels:** backend, performance, scanner

**Summary:**
The scanner's `parse_project_files` and `discover_source_files` functions use `std::fs::read_to_string()` (a blocking I/O call) inside async context. While this is currently acceptable because the scanner runs in a dedicated worker thread (not the main async runtime), the function signatures do not document this requirement, and a future refactor could accidentally call them from async handlers.

**Acceptance Criteria:**

- [ ] Use `tokio::fs::read_to_string()` for async-compatible file I/O
- [ ] Or document that these functions should only be called from `spawn_blocking`
- [ ] Add a `tracing::span` to measure file I/O time separately

**Difficulty:** Beginner

---

# 4. Backend: Database & Storage

## Issue #32 — SQL injection via dynamic query building in `finding_repository`

**Labels:** backend, bug, security, database

**Summary:**
`src/database/repositories/finding_repository.rs:115-128` builds SQL dynamically using `format!()` with user-supplied filter parameters:

```rust
query.push_str(&format!(" AND severity = ${}", param_index));
```

While sqlx's `query_as` ultimately uses bind parameters, the dynamic SQL construction is fragile. If a future refactor moves to raw string interpolation, injection becomes possible. Moreover, the `file_path` filter uses a `LIKE` pattern which can be exploited for pattern-based enumeration even with bind params.

**Acceptance Criteria:**

- [ ] Replace dynamic query building with a structured query builder or conditional `.bind()` chains
- [ ] Validate that `file_path` does not contain wildcard characters if `LIKE` is unintended
- [ ] Add a test for each filter path (severity only, category only, file_path only, all combined)

**Difficulty:** Advanced

## Issue #33 — Dashboard route uses raw SQL with string interpolation for severity filters

**Labels:** backend, bug, security, database

**Summary:**
`src/api/routes/dashboard.rs` contains six separate raw SQL queries with near-identical JOIN patterns (count projects, count scans, count findings, critical_findings, high_findings, medium_findings, average_score, severity breakdown). Each query hardcodes severity strings like `"Critical"`, `"High"`, `"Medium"` inline. This is brittle if the enum values change and creates 7 round trips instead of 1-2 consolidated queries.

**Acceptance Criteria:**

- [ ] Consolidate into a single query that returns all counts in one round trip
- [ ] Use parameterized severity values instead of hardcoded strings
- [ ] Add caching with a Redis-backed TTL for dashboard data

**Difficulty:** Intermediate

## Issue #34 — Register endpoint uses raw SQL for member insert instead of repository

**Labels:** backend, bug, refactor

**Summary:**
`src/api/routes/auth.rs:96-109` executes a raw `sqlx::query("INSERT INTO organization_members ...")` with all field bindings inline, bypassing the `OrganizationMember` model and repository layer. This duplicates the insert logic and could diverge from the schema if columns are added or renamed.

**Acceptance Criteria:**

- [ ] Create an `OrganizationMemberRepository` or add a method to the existing organization repository
- [ ] Replace the raw SQL with the repository method
- [ ] Add a test that verifies member creation after user registration

**Difficulty:** Intermediate

## Issue #35 — No data retention policy for scans, findings, or reports

**Labels:** backend, feature, performance

**Summary:**
Scan results and findings accumulate indefinitely with no deletion or archival mechanism. Over time, database size grows unbounded, degrading query performance on dashboards and list endpoints. There is no TTL or cleanup job.

**Acceptance Criteria:**

- [ ] Add a `retention_days` config option (default 90 days for raw findings, 365 for scan summaries)
- [ ] Create a scheduled cleanup job that soft-deletes or archives expired records
- [ ] Add an admin endpoint to configure per-project retention policies
- [ ] Add an index on `created_at` for the deletion query

**Difficulty:** Intermediate

## Issue #36 — No scan result caching strategy

**Labels:** backend, feature, performance

**Summary:**
Every call to `/v1/scans/{id}/result` and `/v1/scans/{id}` queries PostgreSQL directly, even for completed scans whose results never change. There is no Redis-based caching layer for finalized scan results, leading to unnecessary database load for frequently accessed results.

**Acceptance Criteria:**

- [ ] Cache completed scan results in Redis with a TTL of 1 hour
- [ ] Invalidate the cache only when a scan is retried (new result)
- [ ] Return cached results directly in the API handler

**Difficulty:** Intermediate

## Issue #37 — Dashboard route contains 7 repetitive raw SQL queries

**Labels:** backend, refactor, performance

**Summary:**
`src/api/routes/dashboard.rs` contains 7 separate raw SQL queries that differ only in the `SELECT` expression and the query name. They all join the same 4 tables (`findings → scan_results → scan_jobs → projects`) and filter by `organization_id`. This can be consolidated into 1-2 queries with `COUNT(*) FILTER(WHERE ...)` or subqueries.

**Acceptance Criteria:**

- [ ] Consolidate all count queries into a single SQL statement
- [ ] Move the query into a `DashboardRepository`
- [ ] Add a benchmark to measure dashboard performance

**Difficulty:** Intermediate

## Issue #38 — `finding_repository.list_with_filters` has `unused_assignments` suppression

**Labels:** backend, refactor, code-quality

**Summary:**
`src/database/repositories/finding_repository.rs:107` contains `#[allow(unused_assignments)]` on `param_index`. The variable is incremented but never read. This indicates dead code where the parameter binding logic was partially implemented. Either use `param_index` to build proper bindings or remove the variable.

**Acceptance Criteria:**

- [ ] Remove the `#[allow(unused_assignments)]` suppression
- [ ] Either use `param_index` for its intended purpose or remove it
- [ ] Clean up the dynamic query construction

**Difficulty:** Beginner

## Issue #39 — No database indexes on key foreign key columns

**Labels:** backend, performance, database

**Summary:**
The migrations create tables but do not define indexes beyond the primary key. The dashboard queries, finding list queries, and scan listing queries all perform sequential scans on large tables. Critical missing indexes include: `scan_jobs(project_id)`, `scan_results(scan_job_id)`, `findings(scan_result_id, severity)`, `projects(organization_id)`, and `findings(created_at)`.

**Acceptance Criteria:**

- [ ] Add migration scripts for all missing indexes
- [ ] Run `EXPLAIN ANALYZE` on each query pattern to verify index usage
- [ ] Add index creation to the migration plan

**Difficulty:** Intermediate

---

# 5. Backend: Integration & Contracts

## Issue #40 — Webhook endpoint uses hardcoded placeholder values

**Labels:** backend, bug, api

**Summary:**
`src/api/routes/webhooks.rs:18-45` creates a `github_installations` record with hardcoded `org_id = uuid::Uuid::new_v4()` and sets `account_login = "pending"`, `account_type = "Organization"`, `repository_selection = "selected"` as literal strings. The `org_id` is never linked to an actual authenticated user or organization, making the record orphaned and unreachable.

**Acceptance Criteria:**

- [ ] Require authentication and extract the organization ID from the auth context
- [ ] Replace hardcoded placeholder strings with values from the GitHub API response
- [ ] Verify the installation ID actually belongs to the caller's GitHub App
- [ ] Add tests for duplicate registration, missing auth, and invalid installation_id

**Difficulty:** Intermediate

## Issue #41 — Webhook installation registers with nil user context

**Labels:** backend, bug, api, security

**Summary:**
`src/api/routes/webhooks.rs:14-51`: The `github_install` endpoint has no authentication requirements. Anyone can POST to `/v1/webhooks/github` with an arbitrary `installation_id`. The handler creates a `github_installations` record with a randomly generated `organization_id` that is never linked to any real organization or user.

**Acceptance Criteria:**

- [ ] Require authentication on the webhook registration endpoint
- [ ] Associate the installation with the caller's organization
- [ ] Verify the installation actually exists via the GitHub API before storing it

**Difficulty:** Intermediate

## Issue #42 — No webhook event delivery mechanism

**Labels:** backend, feature, integration

**Summary:**
A `webhooks` table exists (`migrations/20250101000012_create_webhooks.sql`) and a `Webhook` model is defined, but there is no event delivery system — no HTTP callback, no retry logic, no signing of payloads. The `WebhookDedup` cache key only handles deduplication of incoming GitHub webhook events, not outgoing webhook dispatch to user-configured URLs.

**Acceptance Criteria:**

- [ ] Design the webhook event schema (scan.completed, finding.opened, etc.)
- [ ] Implement an HTTP delivery worker that sends signed payloads to registered webhook URLs
- [ ] Add retry with exponential backoff (max 3 retries)
- [ ] Add a webhook test endpoint or UI for testing deliveries

**Difficulty:** Advanced

## Issue #43 — No GitHub check run update during scan progress

**Labels:** backend, feature, integration

**Summary:**
When a scan is triggered by a GitHub commit/PR, the system creates a check run but never updates its status as the scan progresses. Currently, the status only flips to "completed" or "failed" at the end. GitHub users see a pending check run with no intermediate status for potentially minutes-long scans.

**Acceptance Criteria:**

- [ ] Call the GitHub API to update check run status at major milestones (parsing, rule execution, report generation)
- [ ] Use the `ScanStatusCache` progress callback to drive updates
- [ ] Add annotations to the check run for each finding

**Difficulty:** Advanced

## Issue #44 — No contract template management API

**Labels:** backend, feature, contracts

**Summary:**
The `ContractService` supports listing supported contracts and deploying them, but there is no API to manage contract templates directly — no upload of custom WASM, no listing of WASM files on disk, no validation. The `SUPPORTED_CONTRACTS` constant is hardcoded.

**Acceptance Criteria:**

- [ ] Add an endpoint to list available WASM files in the contracts directory
- [ ] Add an endpoint to upload custom WASM to a project
- [ ] Validate WASM files against Soroban requirements before storing
- [ ] Store custom WASM in the database or object storage

**Difficulty:** Intermediate

---

# 6. Backend: Testing & Quality

## Issue #45 — `cli/commands.rs` uses `panic!` in test code instead of `unwrap` or `assert`

**Labels:** backend, refactor, testing

**Summary:**
`src/cli/commands.rs:180` and 7 other locations use `panic!("expected scan command")` inside `match` arms in test code. These should use `if let` or direct field access instead of match + panic, which is noisy and less idiomatic.

**Acceptance Criteria:**

- [ ] Replace `match cli.command { Commands::Scan(ref a) => a, _ => panic!(...) }` with `let Commands::Scan(ref a) = cli.command;` or use `assert!(matches!(...))`
- [ ] Use `unwrap()` or `expect()` for test assertions instead of `panic!()`

**Difficulty:** Beginner

## Issue #46 — No integration tests for API endpoints

**Labels:** backend, testing, api

**Summary:**
The `axum-test` crate is listed as a dev-dependency in `Cargo.toml`, and there is exactly one `#[tokio::test]` across the entire codebase. There are zero integration tests that spin up the router, call endpoints, and verify responses. All 255 existing tests are pure unit tests with no database or network interaction.

**Acceptance Criteria:**

- [ ] Add integration tests for each route module using `axum-test`
- [ ] Test success paths, error paths, auth rejection, and input validation
- [ ] Use testcontainers or sqlx::test fixtures for database-backed tests
- [ ] Add a CI job that runs integration tests with PostgreSQL and Redis

**Difficulty:** Advanced

## Issue #47 — No contract tests for the Soroban RPC client

**Labels:** backend, testing, contracts

**Summary:**
The `SorobanRpcClient` defined in `src/contracts/rpc.rs` has no unit or integration tests. The HTTP-based RPC client makes real network calls with no mock layer or test harness. The `ContractDeployer` similarly lacks tests for WASM upload, contract creation, and health check.

**Acceptance Criteria:**

- [ ] Add a mock HTTP server or trait-based test double for the RPC client
- [ ] Test: successful upload, successful deploy, RPC error response, network timeout
- [ ] Test `ContractDeployer` with a mock `SorobanRpcClient`

**Difficulty:** Advanced

## Issue #48 — No tests for database repository implementations

**Labels:** backend, testing, database

**Summary:**
None of the 10 database repository implementations have tests. Methods like `create`, `find_by_id`, `update`, `delete`, and various list methods are untested. The `finding_repository::list_with_filters` method — which has the dynamic SQL builder and `#[allow(unused_assignments)]` — is completely untested.

**Acceptance Criteria:**

- [ ] Add a test database setup with migrations for repository tests
- [ ] Test each CRUD operation for all repositories
- [ ] Specifically test `list_with_filters` with every filter combination

**Difficulty:** Advanced

## Issue #49 — No tests for AI provider

**Labels:** backend, testing, ai

**Summary:**
The `AiProvider` trait has two implementations (`OllamaProvider` and `DisabledProvider`), neither with tests. The Ollama provider makes real HTTP calls. The `DisabledProvider` returns hardcoded errors but its behavior is never tested.

**Acceptance Criteria:**

- [ ] Add a mock `AiProvider` for testing
- [ ] Test the `DisabledProvider` returns expected errors
- [ ] Test the AI route handlers with a mock provider
- [ ] Test error handling when Ollama is unreachable

**Difficulty:** Intermediate

## Issue #50 — No tests for Redis cache operations

**Labels:** backend, testing, cache

**Summary:**
`src/cache/redis.rs` defines `SessionStore`, `RateLimiter`, `WebhookDedup`, and `ScanStatusCache` — all with no tests. The Redis command patterns (ZADD, ZCOUNT, SET NX EX, BRPOP) are never verified against actual Redis behavior.

**Acceptance Criteria:**

- [ ] Use a local Redis instance or `redis-test` crate for testing cache operations
- [ ] Test: rate limit allowed, rate limit exceeded, window reset, dedup idempotency
- [ ] Test: session store CRUD, scan status cache set/get/mark_cancelled

**Difficulty:** Intermediate

## Issue #51 — No tests for scan job queue and worker

**Labels:** backend, testing, jobs

**Summary:**
The `JobQueue` (enqueue/dequeue) and `WorkerPool`/`Worker` (background job processing) have zero tests. The queue's Redis LPUSH/BRPOP mechanics, timeout behavior, and error handling paths are untested.

**Acceptance Criteria:**

- [ ] Add integration tests for the queue with a Redis instance
- [ ] Test: enqueue → dequeue, empty queue timeout, malformed payload handling
- [ ] Test worker error handling (scan failure, DB failure, panic recovery)

**Difficulty:** Advanced

## Issue #52 — No benchmarks run in CI

**Labels:** backend, testing, ci/cd

**Summary:**
Four benchmarks are defined (`parser`, `rule_engine`, `full_scan`, `formatting`) using Criterion, but there is no CI step that runs benchmarks or tracks performance regressions. The benchmark code may be broken or stale without anyone noticing.

**Acceptance Criteria:**

- [ ] Add a `cargo bench` step to the CI workflow (nightly or scheduled)
- [ ] Store benchmark results as CI artifacts
- [ ] Add a performance regression check (e.g., 5% threshold) using `criterion-compare`

**Difficulty:** Intermediate

## Issue #53 — Integration tests require external services but only unit tests run

**Labels:** backend, ci/cd

**Summary:**
The CI workflow runs `cargo test`, but 255 unit tests pass without database or Redis because they are pure logic tests. The 15 database migrations, 10 repository implementations, cache operations, and full scan pipeline are never exercised in CI because there are no integration tests that connect to the PostgreSQL and Redis service containers that the CI already provisions.

**Acceptance Criteria:**

- [ ] Add a separate `cargo test --test integration` step that runs tests annotated with `#[sqlx::test]` or using `axum-test`
- [ ] Configure the test database URL and Redis URL from the CI service containers
- [ ] Run `cargo test` for unit tests first, then integration tests

**Difficulty:** Intermediate

## Issue #54 — No integration test stage for contracts module

**Labels:** backend, ci/cd

**Summary:**
The `ContractDeployer` and `SorobanRpcClient` connect to external services (Soroban RPC endpoints). There are no CI tests that validate contract deployment against an actual Stellar network (testnet or local container). Changes to the contracts module could silently break deployment.

**Acceptance Criteria:**

- [ ] Set up a local Stellar/Soroban container (stellar/quickstart) in CI
- [ ] Add integration tests that deploy contracts to the local network
- [ ] Verify the full deployment flow: upload WASM → create contract → verify deployment record

**Difficulty:** Advanced

## Issue #55 — No latency or performance regression tracking

**Labels:** backend, ci/cd

**Summary:**
Four Criterion benchmarks exist but are never executed in CI. Performance regressions in the parser, rule engine, or scanner are not detected until they reach production. There is no baseline comparison against previous runs.

**Acceptance Criteria:**

- [ ] Add a `cargo bench` job to CI (run on schedule or on-demand, not on every PR)
- [ ] Store baseline results in a cache or S3-compatible storage
- [ ] Comment on PRs if benchmarks show >5% regression

**Difficulty:** Intermediate

---

# 7. Backend: Security

## Issue #56 — `CorsLayer::permissive()` allows any origin in production

**Labels:** backend, bug, security

**Summary:**
`src/api/mod.rs:33` uses `.layer(CorsLayer::permissive())` which sets `Access-Control-Allow-Origin: *` and allows all methods and headers. This is acceptable only during development. In production, this exposes the API to cross-origin attacks and data exfiltration.

**Acceptance Criteria:**

- [ ] Read allowed origins from an environment variable (`CORS_ALLOWED_ORIGINS`)
- [ ] Use `CorsLayer::new().allow_origin(allow_origin)` with specific origins
- [ ] Default to `permissive` only when `ENV=development`

**Difficulty:** Intermediate

## Issue #57 — No audit log for security-critical operations

**Labels:** backend, feature, security

**Summary:**
An `audit_log` table exists in the migrations (`migrations/20250101000010_create_audit_logs.sql`) and an `AuditLog` model is defined in `src/database/models/audit_log.rs`, but no code writes to the audit log anywhere in the codebase. Critical operations like user registration, login, project deletion, API key creation, and role changes go unlogged.

**Acceptance Criteria:**

- [ ] Create an `AuditLogRepository` with a `log_event()` method
- [ ] Add audit events to: user registration, login, project CRUD, scan trigger, API key operations, role changes
- [ ] Add an `audit` endpoint for admins to query the log
- [ ] Add TTL-based retention policy for audit entries

**Difficulty:** Intermediate

## Issue #58 — JWT access secret defaults to predictable development value

**Labels:** backend, security, configuration

**Summary:**
`src/auth/jwt.rs:43-44`: If `JWT_ACCESS_SECRET` is not set, the server uses `"astinel-access-secret-dev"`. This is a well-known value that an attacker can use to forge arbitrary access tokens with any user ID, email, and role.

**Acceptance Criteria:**

- [ ] Require `JWT_ACCESS_SECRET` in production mode (validate at startup)
- [ ] Generate a strong default in development mode (at least 32 bytes of entropy)
- [ ] Log a warning if using the fallback default

**Difficulty:** Intermediate

## Issue #59 — API key hash uses SHA-256 without salt

**Labels:** backend, security, auth

**Summary:**
`src/api/middleware.rs:29-34` computes `SHA-256(api_key)` for storage and lookup. SHA-256 is a fast hash without a salt, making precomputed rainbow tables effective if the hash column is exposed. Argon2 is already a dependency but is not used for API key hashing.

**Acceptance Criteria:**

- [ ] Use Argon2id (already in dependencies) for API key hashing
- [ ] Store a random salt alongside the hash
- [ ] Rehash existing keys on first use (or force key rotation)
- [ ] Add a migration to support the new hash format

**Difficulty:** Intermediate

## Issue #60 — No input size limits on request bodies

**Labels:** backend, security, api

**Summary:**
There is no limit on request body sizes anywhere in the Axum router or middleware. An attacker can POST a multi-gigabyte payload to any endpoint (e.g., scan trigger, AI analysis, webhook receiver), causing out-of-memory conditions. Axum has built-in body size limits via `DefaultBodyLimit`, but it is not configured.

**Acceptance Criteria:**

- [ ] Add `layer(DefaultBodyLimit::max(1024 * 1024))` (1 MB) to the router
- [ ] Exempt specific endpoints that need larger payloads (e.g., WASM upload)
- [ ] Return 413 Payload Too Large on oversized requests

**Difficulty:** Beginner

## Issue #61 — No secret scanning or credential leak detection

**Labels:** backend, security, configuration

**Summary:**
The `.env.example` file contains default secrets like `JWT_ACCESS_SECRET=astinel-access-secret-dev` and `DB_PASSWORD=postgres`. If these defaults are used in production (which the code allows), they are trivially guessable. The repository has no secret scanning in CI to catch accidental commits of real credentials.

**Acceptance Criteria:**

- [ ] Add a CI job with `trufflehog` or `gitleaks` to scan for secrets
- [ ] Remove all default production secrets from `.env.example` (use placeholders like `change-me`)
- [ ] Add a startup validation that warns if production secrets match known defaults

**Difficulty:** Intermediate

## Issue #62 — `verify_webhook_signature` uses constant-time comparison incorrectly

**Labels:** backend, refactor, security

**Summary:**
`src/services/github.rs:137`: `computed == expected` uses Rust's string equality, which is a short-circuit comparison. For HMAC verification, this is vulnerable to timing attacks. While less critical in a server-side context, HMAC comparison should use a constant-time function.

**Acceptance Criteria:**

- [ ] Use `hmac::Mac::verify_slice()` or `subtle::ConstantTimeEq` for the comparison
- [ ] Add a test verifying that timing differences are not observable

**Difficulty:** Intermediate

---

# 8. Backend: Developer Experience

## Issue #63 — Database connection config `from_url` silently ignores URL params

**Labels:** backend, enhancement, configuration

**Summary:**
`src/database/connection.rs:79-99`: `from_url` parses the DATABASE_URL manually with `split_once('@')` and `split_once(':')` instead of using a proper URL parser. SSL parameters, connection timeouts, and pool settings in the URL query string are silently ignored.

**Acceptance Criteria:**

- [ ] Use `url::Url` to properly parse the connection string
- [ ] Extract query parameters for SSL mode, pool size, etc.
- [ ] Add tests for various URL formats

**Difficulty:** Intermediate

## Issue #64 — Env var validation happens at runtime, not at startup

**Labels:** backend, enhancement, configuration

**Summary:**
Critical environment variables (`JWT_ACCESS_SECRET`, `DATABASE_URL`, `REDIS_URL`) are accessed with `.unwrap_or_else(|_| "dev-default")` throughout the codebase. Missing production config is silently replaced with development defaults. The server starts successfully only to fail on the first request with confusing errors.

**Acceptance Criteria:**

- [ ] Create a `Settings` struct that validates all required env vars at startup
- [ ] Fail fast with a clear error message listing all missing variables
- [ ] Distinguish between required and optional variables

**Difficulty:** Intermediate

## Issue #65 — No OpenAPI spec auto-generation

**Labels:** backend, enhancement, documentation

**Summary:**
`API.md` is hand-written and will inevitably drift from the implementation. The `/v1/openapi.json` endpoint exists but is explicitly documented as a "static stub" (`API.md:31`). There is no auto-generated OpenAPI specification from the Axum router.

**Acceptance Criteria:**

- [ ] Integrate `utoipa` or `aide` for OpenAPI spec generation from route handlers
- [ ] Replace the static stub with the generated spec
- [ ] Add a Swagger UI endpoint for interactive API documentation

**Difficulty:** Advanced

## Issue #66 — `handlers/mod.rs` and `repositories/mod.rs` are empty stubs declared in `lib.rs`

**Labels:** backend, refactor, dead-code

**Summary:**
`src/lib.rs:13` and `src/lib.rs:15` declare `pub mod handlers;` and `pub mod repositories;`, but both directories contain only `mod.rs` with no content. These modules compile to nothing and increase cognitive load for developers navigating the project.

**Acceptance Criteria:**

- [ ] Remove the empty module declarations from `lib.rs`
- [ ] Or populate them with actual code if the directories were intended for future use

**Difficulty:** Beginner

## Issue #67 — Database config has two similar but distinct parsing paths

**Labels:** backend, refactor, configuration

**Summary:**
`src/database/connection.rs` contains `from_env()` (which reads individual DB_HOST, DB_PORT, etc.) and `from_url()` (which parses DATABASE_URL). The two paths produce `DbConfig` structs with different defaults and the URL parser ignores SSL and pool settings. Both paths should produce identical configs.

**Acceptance Criteria:**

- [ ] Unify parsing: `from_env` should check for `DATABASE_URL` first, then fall back to individual vars
- [ ] Use `url::Url` for proper URL parsing in `from_url`
- [ ] Ensure both paths produce identical `DbConfig` for the same logical values

**Difficulty:** Intermediate

## Issue #68 — No module-level doc comments

**Labels:** backend, documentation

**Summary:**
Public modules (ai, auth, cache, cli, config, contracts, core, database, errors, handlers, jobs, middleware, repositories, scanner, services, state, telemetry, utils) have no `//!` module-level documentation explaining their purpose, structure, or usage. The only documentation is the high-level README and ARCHITECTURE files.

**Acceptance Criteria:**

- [ ] Add `//!` doc comments to every `mod.rs`
- [ ] Explain the module's responsibility, key types, and relationships
- [ ] Include cross-references to related modules

**Difficulty:** Beginner

## Issue #69 — No doc comments on public API types and functions

**Labels:** backend, documentation

**Summary:**
Most public structs, enums, trait methods, and function signatures lack `///` doc comments. For example: `ScanRequest`, `ScanRequestBuilder`, `ScanType`, `DefaultScanner::scan()`, `AiProvider` trait methods, all repository traits and implementations, and `AppState` have no docs.

**Acceptance Criteria:**

- [ ] Add `///` doc comments to all public items
- [ ] Include examples in trait method docs
- [ ] Document error conditions and panics

**Difficulty:** Beginner

## Issue #70 — `API.md` is hand-written and incomplete

**Labels:** backend, documentation

**Summary:**
`API.md` documents 50% of the actual API surface. Endpoints for notifications, dashboard, AI analysis, and contracts exist in the code but are not documented. The documented response shapes do not match actual response formats (list_scans returns a bare array, not `{success, data}`).

**Acceptance Criteria:**

- [ ] Update API.md to cover all 14 route modules
- [ ] Document all request/response shapes with examples
- [ ] Document error codes and status codes
- [ ] Automate API doc generation from the OpenAPI spec once implemented

**Difficulty:** Intermediate

## Issue #71 — `ARCHITECTURE.md` does not describe the job worker architecture

**Labels:** backend, documentation

**Summary:**
`ARCHITECTURE.md` describes the scan pipeline (Client → API → Redis → Worker → Parser → Rules → DB) but omits the actual worker pool implementation, the Redis queue mechanics, and the worker lifecycle. New contributors cannot understand how background scan processing works.

**Acceptance Criteria:**

- [ ] Add a sequence diagram for the worker pool startup and job processing loop
- [ ] Document the queue data structures (LPUSH/BRPOP, serialization format)
- [ ] Document the worker error handling and retry policy

**Difficulty:** Beginner

## Issue #72 — No configuration validation at startup

**Labels:** backend, configuration

**Summary:**
The server starts without validating that Redis and PostgreSQL are reachable. If the database is down or the Redis URL is wrong, the server binds to the port successfully but fails on the first request that touches the database, producing a confusing error to the client.

**Acceptance Criteria:**

- [ ] Ping PostgreSQL and Redis at startup, fail fast if unreachable
- [ ] Add `--validate-config` flag to the server and CLI binaries
- [ ] Log all config values (except secrets) at startup for debugging

**Difficulty:** Intermediate

## Issue #73 — `ASTINEL_CONTRACTS_DIR` env var documented but not used by server

**Labels:** backend, configuration

**Summary:**
`.env.example:38` defines `ASTINEL_CONTRACTS_DIR=../Astinel-contracts`, but the server binary never reads this variable. The `ContractDeployer` reads WASM files from a baked-in path, and there is no way to configure the contracts directory at runtime.

**Acceptance Criteria:**

- [ ] Add `ASTINEL_CONTRACTS_DIR` support to the server binary
- [ ] Use it as the base path for WASM file discovery
- [ ] Fall back to a compiled-in default if not set

**Difficulty:** Beginner

## Issue #74 — 29 environment variables with no validation or grouping

**Labels:** backend, configuration

**Summary:**
The codebase reads approximately 29 environment variables across 10+ modules, but there is no centralized configuration struct. Each module reads its own variables independently, making it difficult to audit all available configuration options. The `.env.example` file helps but is not validated against the code.

**Acceptance Criteria:**

- [ ] Create a single `Settings` struct using `config` or `serde` that deserializes from env vars
- [ ] Validate all settings at startup with clear error messages
- [ ] Generate `.env.example` dynamically from the struct

**Difficulty:** Advanced

## Issue #75 — No deny/audit checks in CI workflow

**Labels:** backend, ci/cd, security

**Summary:**
The README documents `cargo deny check` as part of the test suite (`README.md:153`), but the CI workflow in `.github/workflows/ci.yml` only runs `cargo build` and `cargo test`. There is no security advisory audit (cargo-deny), no dependency vulnerability scanning, and no lint step beyond what `cargo test` implies.

**Acceptance Criteria:**

- [ ] Add `cargo clippy -- -D warnings` step to the CI workflow
- [ ] Add `cargo fmt --check` step
- [ ] Add `cargo deny check` step (install cargo-deny via dtolnay/rust-toolchain or separate action)
- [ ] Fail the CI pipeline on any advisory, clippy warning, or formatting issue

**Difficulty:** Intermediate

## Issue #76 — No Docker image build or publish

**Labels:** backend, ci/cd

**Summary:**
There is no Dockerfile, no `.dockerignore`, and no CI step to build and publish a Docker image. The only deployment option is `cargo run --bin astinel-server` from source, which requires the full Rust toolchain and compilation time in production.

**Acceptance Criteria:**

- [ ] Create a multi-stage Dockerfile that builds the server binary and produces a minimal runtime image
- [ ] Add a CI job that builds and publishes the Docker image to GitHub Container Registry
- [ ] Tag images with both `latest` and the Git SHA

**Difficulty:** Intermediate
