# Dynamic Testing Results — n8n Instance Probing

## Methodology
Launched a fresh n8n instance (v2.16.0) and performed comprehensive
unauthenticated reconnaissance, fuzzing, and WebSocket probing.

## Instance Configuration
- Fresh SQLite database
- Default configuration (no special env vars)
- Owner account set up
- No workflows initially (created during testing)

## Test Results Summary

### Unauthenticated Endpoint Discovery
| Endpoint | Method | Status | Auth | Notes |
|----------|--------|--------|------|-------|
| `/rest/settings` | GET | 200 | `allowUnauthenticated` | Returns public settings |
| `/healthz` | GET | 200 | None | Health check |
| `/healthz/readiness` | GET | 200 | None | Readiness check |
| `/rest/options/timezones` | GET | 200 | **None** | Returns 11KB timezone data |
| `/rest/test-webhook/:id` | DELETE | 200 | **None** | Unauthenticated delete |
| `/api/v1/openapi.yml` | GET | 200 | **None** | Full API specification |
| `/.well-known/oauth-authorization-server` | GET | 200 | None | MCP OAuth discovery |
| `/webhook/*` | ALL | Varies | None (by design) | Webhook handlers |
| `/form-waiting/*` | ALL | 200 | None | Form waiting pages |

### Content-Type Confusion
Tested all content types against `/rest/login`:
- `application/json` → 500 (empty body)
- All others → 400 (Zod validation)
- No type confusion exploitable

### HTTP Verb Tampering
- Only registered methods work
- OPTIONS returns 204 (CORS preflight)
- No verb confusion found

### Path Manipulation
- `..` traversal normalized by Express — cannot bypass auth
- `/webhook-test/../../rest/settings` → 200 (path normalized to `/rest/settings`, auth still applies)
- Case-insensitive routing (`/rest/SETTINGS` → 200) — no security impact
- URL encoding (`%2f`) → 404 (not decoded as path separator)
- Null byte injection → 404

### Prototype Pollution
- `__proto__` in JSON body → ignored by Zod validation
- `constructor.prototype` in body → Zod rejects
- Query param pollution → blocked by `qs` library
- No global Object pollution detected

### WebSocket Testing
- **Chat WebSocket (`/chat`)** — Connects without auth, but immediately receives "execution not found" for invalid IDs. Can enumerate execution existence.
- **Push WebSocket (`/rest/push`)** — Upgrade completes at HTTP level, but application immediately sends close frame (opcode 8). Auth middleware rejects.

### Webhook Execution
- Created and activated workflow with Webhook node
- Unauthenticated webhook access confirmed (by design)
- Attacker can send arbitrary data to webhook endpoints
- Response depends on workflow configuration (controlled by admin)
- No code injection through webhook data into expression evaluation (sandboxed)

## Confirmed Vulnerabilities

### 1. Unauthenticated Test Webhook Deletion (DoS)
`DELETE /rest/test-webhook/:id` has no authentication. Any network attacker
can cancel test webhooks by ID, disrupting developer workflow testing.

### 2. Unauthenticated API Specification Exposure
`GET /api/v1/openapi.yml` returns the full Public API specification without
authentication, revealing all API endpoints, parameters, and schemas.

### 3. Chat WebSocket Execution ID Oracle
The `/chat` WebSocket accepts connections without authentication and reveals
whether specific execution IDs exist ("does not exist" vs connection stays open).
This enables execution ID enumeration.

## Not Exploitable (Confirmed by Dynamic Testing)
- Path traversal through webhook prefix → auth still applies
- Prototype pollution via any parser → blocked
- Push WebSocket unauthorized access → immediately closed
- Content-type confusion → Zod validation catches
- Expression injection via webhook data → sandboxed in isolated-vm
