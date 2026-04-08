# n8n Security Vulnerability Report — Unauthenticated Attack Chains

## Vulnerability 1: Unauthenticated RCE via Fresh Instance Owner Takeover

### Classification
- **Type**: Unauthenticated Remote Code Execution (RCE)
- **CVSS 3.1**: 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **CWE**: CWE-287 (Improper Authentication), CWE-269 (Improper Privilege Management)

### Summary
Every n8n instance starts in a state where the `POST /api/v1/owner/setup`
endpoint (`skipAuth: true`) allows any unauthenticated network attacker to
register as the instance owner. Once owner, the attacker can create a
workflow with a Code node and trigger it via an unauthenticated webhook,
achieving arbitrary command execution on the server.

### Affected Code

**Owner setup endpoint** — `packages/cli/src/controllers/owner.controller.ts`:
```typescript
@Post('/setup', { skipAuth: true })  // <-- No authentication required
async setupOwner(req: AuthenticatedRequest, res: Response, @Body payload: OwnerSetupRequestDto) {
    const owner = await this.ownershipService.setupOwner(payload);
    this.authService.issueCookie(res, owner, ...);
    return await this.userService.toPublic(owner, ...);
}
```

**Guard bypass** — `packages/cli/src/services/ownership.service.ts`:
```typescript
async hasInstanceOwner() {
    return await this.userRepository.exists({
        where: [
            { role: { slug: GLOBAL_OWNER_ROLE.slug }, lastActiveAt: Not(IsNull()) },
            { role: { slug: GLOBAL_OWNER_ROLE.slug }, password: Not(IsNull()) },
        ],
    });
}
// On fresh instance: shell user has lastActiveAt=NULL and password=NULL → returns false
```

### Attack Chain (5 steps, all from unauthenticated network access)

```
1. GET  /api/v1/settings          → Detect showSetupOnFirstLoad: true
2. POST /api/v1/owner/setup       → Claim ownership, receive auth cookie
3. POST /api/v1/workflows         → Create workflow with Code node + Webhook trigger
4. POST /api/v1/workflows/:id/activate → Activate the workflow
5. GET  /webhook/:path            → Trigger Code node execution → RCE
```

### Proof of Concept

See `exploit.py` — a complete working exploit that demonstrates the full chain.

### Impact

- Full server compromise via arbitrary command execution
- Access to all stored credentials (decryptable with the encryption key)
- Lateral movement via stored API credentials
- Data exfiltration of all workflow data
- Persistent backdoor via activated webhook workflows

### Window of Exposure

- From n8n startup → until legitimate admin completes setup
- In automated/containerized deployments, this window can be significant
- In Kubernetes/Docker Compose setups, the instance may be network-accessible
  before the admin even knows it's running

---

## Vulnerability 2: Unauthenticated Test Webhook Cancellation (DoS)

### Classification
- **Type**: Unauthenticated Denial of Service
- **CVSS 3.1**: 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L
- **CWE**: CWE-306 (Missing Authentication for Critical Function)

### Summary
The `DELETE /api/v1/test-webhook/:id` endpoint is registered directly on the
Express app WITHOUT any authentication middleware. Any unauthenticated
network attacker can cancel test webhooks belonging to any user's active
workflow test sessions.

### Affected Code

**`packages/cli/src/abstract-server.ts`** (lines 282-287):
```typescript
if (this.testWebhooksEnabled) {
    const testWebhooks = Container.get(TestWebhooks);
    // TODO UM: check if this needs validation with user management.
    this.app.delete(
        `/${this.restEndpoint}/test-webhook/:id`,
        send(async (req) => await testWebhooks.cancelWebhook(req.params.id)),
    );
}
```

Note the TODO comment: `"check if this needs validation with user management"`.
This endpoint was intentionally left without auth and never secured.

### Impact

- An attacker can cancel any active test webhook, disrupting developer workflow
- If an attacker can enumerate/guess workflow IDs, they can prevent all testing
- The `cancelWebhook` method also sends a push notification to the user's
  browser via `this.push.send()`, potentially causing UI disruption

---

## Vulnerability 3: Token Exchange JWT Signature Bypass

### Classification
- **Type**: Authentication Bypass
- **CVSS 3.1**: 8.1 (High) — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
- **CWE**: CWE-347 (Improper Verification of Cryptographic Signature)

### Summary
The `POST /api/v1/auth/oauth/token` endpoint (RFC 8693 token exchange) uses
`jwt.decode()` instead of `jwt.verify()` to process external JWTs, accepting
ANY forged token without cryptographic signature verification.

### Affected Code

**`packages/cli/src/modules/token-exchange/token-exchange.service.ts`**:
```typescript
private decodeAndValidate(token: string): ExternalTokenClaims {
    const decoded = this.jwtService.decode<unknown>(token);  // <-- NO VERIFICATION!
    return ExternalTokenClaimsSchema.parse(decoded);
}
```

### Prerequisites
- `N8N_TOKEN_EXCHANGE_ENABLED=true`
- `N8N_ENV_FEAT_TOKEN_EXCHANGE=true`
- TOKEN_EXCHANGE license feature enabled

### Impact
When token exchange is enabled, any attacker can forge arbitrary identity
claims and receive a valid n8n-signed JWT access token.

---

## Vulnerability 4: Shared JWT Secret Cross-Purpose Token Confusion

### Classification
- **Type**: Improper Access Control
- **CVSS 3.1**: 6.5 (Medium)
- **CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

### Summary
All JWT token types (auth cookies, password reset, invitations, API keys,
token exchange) share a single signing secret. Invitation token verification
(`processTokenBasedInvite`) does not validate `issuer` or `audience` claims,
only checking for `inviterId`/`inviteeId` fields.

### Affected Code

**`packages/cli/src/services/user.service.ts`**:
```typescript
const decoded = this.jwtService.verify<{ inviterId: string; inviteeId: string }>(token);
// No issuer or audience validation — any JWT signed with the shared secret
// that contains inviterId and inviteeId would be accepted
```
