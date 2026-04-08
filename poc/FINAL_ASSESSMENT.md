# n8n Security Deep-Dive — Final Assessment

## Methodology

Exhaustive static analysis of all unauthenticated code paths reachable from
pure network access against a fully operational n8n instance with default
configuration and owner already set up. Traced data flow from HTTP ingress
through parsing, processing, expression evaluation, file I/O, and response
rendering.

## Attack Surface Analyzed

### Always-Available Unauthenticated Endpoints
| Endpoint | Purpose | Auth | Verdict |
|----------|---------|------|---------|
| `GET /healthz` | Health check | None | No data exposure |
| `GET /api/v1/settings` | Public settings | `allowUnauthenticated` | Limited info disclosure by design |
| `GET /api/v1/binary-data/signed` | Signed binary download | JWT token | Properly validated |
| `POST /api/v1/login` | Authentication | `skipAuth` | Rate-limited in prod |
| `POST /api/v1/forgot-password` | Password reset | `skipAuth` | Rate-limited + jitter |
| `POST /api/v1/change-password` | Password change | `skipAuth` | Requires valid reset token |
| `GET /api/v1/resolve-signup-token` | Invitation resolve | `skipAuth` | Requires valid invite JWT |
| `POST /api/v1/invitations/accept` | Accept invitation | `skipAuth` | Requires valid invite JWT |
| `POST /api/v1/owner/setup` | Owner setup | `skipAuth` | Guarded by `hasInstanceOwner()` |
| `ALL /webhook/*` | Live webhooks | None (by design) | Triggers user-defined workflows |
| `ALL /webhook-waiting/*` | Waiting webhooks | Token validated | Old executions skip validation |
| `ALL /form/*` | Form webhooks | None (by design) | Triggers user-defined workflows |
| `ALL /form-waiting/*` | Waiting forms | Token validated | Old executions skip validation |
| `GET/POST /api/v1/ph/*` | PostHog proxy | `skipAuth` | Fixed target URL |
| `GET /api/v1/sso/saml/metadata` | SAML metadata | `skipAuth` | Read-only metadata |

### Data Processing Pipeline
| Component | Technology | Vulnerability Class | Result |
|-----------|-----------|-------------------|--------|
| XML body parsing | xml2js v0.6.2 | XXE, Entity expansion | **SAFE** — Entities blocked |
| JSON body parsing | `JSON.parse()` | Prototype pollution | **SAFE** — Native parser |
| Query string parsing | qs (extended) | Prototype pollution | **SAFE** — `__proto__` blocked |
| URL-encoded body | `querystring.parse()` | Injection | **SAFE** — maxKeys=1000 |
| Multipart/form-data | multer | File upload abuse | **SAFE** — Controlled by workflow config |
| Content encoding | gzip/deflate | Decompression bomb | **SAFE** — payloadSizeMax limit |

### Expression Evaluation
| Layer | Protection | Result |
|-------|-----------|--------|
| AST sanitization | PrototypeSanitizer, ThisSanitizer | Blocks `__proto__`, constructor, `this` abuse |
| Computed member access | Runtime sanitizer function | Blocks dynamic property access to unsafe props |
| Execution isolation | `isolated-vm` V8 isolate | Memory-limited, no Node.js API access |
| Class extension | Blocked | `Function`, `GeneratorFunction`, etc. blocked |
| Spread elements | Safe resolution | `...process`, `...global` intercepted |
| `with` statement | Blocked | Throws ExpressionWithStatementError |

### File System Operations
| Operation | Protection | Result |
|-----------|-----------|--------|
| Binary data read | `resolvePath()` + `path.relative()` check | **SAFE** — Path traversal blocked |
| Binary data write | Same as above | **SAFE** |
| Binary data signed access | JWT signature verification | **SAFE** — Requires signing secret |

### Response Security
| Vector | Protection | Result |
|--------|-----------|--------|
| Header injection (CRLF) | `validateHeaderName()` + `validateHeaderValue()` | **SAFE** |
| CSP bypass | Protected headers blocked, CSP enforced on sandbox | **SAFE** |
| Clickjacking | X-Frame-Options: SAMEORIGIN (prod) | **SAFE** in prod |

### WebSocket/Push
| Vector | Protection | Result |
|--------|-----------|--------|
| Unauthenticated connection | Auth middleware required | **SAFE** |
| Origin bypass | `validateOriginHeaders()` in production | **SAFE** in prod |
| Cross-user message injection | pushRef + userId scoping | **SAFE** |

## Findings

### Finding 1: Waiting Webhook Backwards-Compatibility Token Skip (Low)
**Location**: `packages/cli/src/webhooks/waiting-webhooks.ts:190-207`

Old executions created before the `resumeToken` feature was added can be
resumed without any token validation. The code explicitly skips validation
when `execution?.data.resumeToken` is falsy:

```typescript
if (execution?.data.resumeToken) {
    // Token validation happens here
} 
// If no resumeToken → continues WITHOUT validation
```

**Impact**: An attacker who knows/guesses execution IDs can resume old
waiting-state executions, potentially receiving workflow data in the response.
Execution IDs are sequential integers in SQLite or UUIDs in PostgreSQL.

**Preconditions**: Requires a waiting execution created before the token
validation feature was added, and knowledge of the execution ID.

### Finding 2: PostHog Unauthenticated Proxy (Informational)
**Location**: `packages/cli/src/controllers/posthog.controller.ts`

The `/api/v1/ph/*` endpoint proxies all requests to the PostHog API host
without authentication. While the target is hardcoded to
`https://us.i.posthog.com`, this creates an open relay to PostHog that
could be abused for:
- Anonymous PostHog API access via the n8n instance
- Bandwidth amplification

**Preconditions**: Diagnostics must be enabled (default: true).

## Conclusion

After exhaustive analysis of all unauthenticated code paths, **no
unconditional unauthenticated RCE chain was found** that works against a
fully operational n8n production instance with default configuration and
owner already set up.

n8n implements comprehensive defense-in-depth:
- Expression evaluation uses V8 isolates with AST-level sanitization
- File operations validate paths against directory traversal
- HTTP headers are validated against injection
- JWT tokens use proper signature verification
- Prototype pollution is blocked at multiple levels
- XML parsing blocks entity injection
- Rate limiting is active in production mode

The codebase demonstrates a mature security posture with multiple overlapping
protection layers that prevent chaining lower-severity issues into
high-impact exploitation paths.
