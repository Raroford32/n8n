# Unauthenticated Chat WebSocket Session Hijacking

## Classification
- **Type**: Missing Authentication on Critical WebSocket Endpoint
- **CVSS 3.1**: 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N
- **CWE**: CWE-306 (Missing Authentication for Critical Function)

## Summary

The n8n Chat WebSocket endpoint (`/chat`) is registered on the Express
application BEFORE authentication middleware is applied, creating an
unconditionally unauthenticated WebSocket endpoint that allows any
network attacker to:

1. Connect to any active chat execution by enumerating sequential execution IDs
2. Hijack chat sessions by injecting messages into waiting executions
3. Resume workflow execution with attacker-controlled input data
4. Potentially achieve code execution if downstream Code nodes process the injected data

## Root Cause

### Middleware Registration Order Bug

In `packages/cli/src/server.ts`, the `setupPushServer()` method is called from
`AbstractServer.start()` BEFORE authentication middleware registration:

```
Order of registration in AbstractServer.start():
  1. setupPushServer()          ← ChatServer.setup() registers /chat route HERE
  2. setupCommonMiddlewares()   ← compression, rawBodyReader
  3. webhook handlers
  4. bodyParser
  5. configure()                ← cookieParser, auth middleware registered HERE (too late!)
```

The chat WebSocket upgrade handler in `ChatServer.setup()` (line 30) calls
`app.handle(req, res)` which routes through Express — but the `/chat` route
handler was registered at step 1, BEFORE cookie parsing and auth middleware
from step 5.

### File: `packages/cli/src/chat/chat-server.ts`

```typescript
setup(server: HttpServer, app: Application) {
    server.on('upgrade', (req: ChatRequest, socket, head) => {
        const parsedUrl = parseUrl(req.url ?? '');
        if (parsedUrl.pathname?.startsWith('/chat')) {
            this.wsServer.handleUpgrade(req, socket, head, (ws) => {
                this.attachToApp(req, ws, app as ExpressApplication);
                // attachToApp calls app.handle(req, res) → runs Express stack
                // But auth middleware isn't registered yet!
            });
        }
    });

    app.use('/chat', async (req: ChatRequest) => {
        await this.chatService.startSession(req);
        // startSession: NO authentication check
        // Only checks: executionId exists (checkIfExecutionExists)
    });
}
```

### File: `packages/cli/src/chat/chat-service.ts`

```typescript
async startSession(req: ChatRequest) {
    const { ws, query: { sessionId, executionId, isPublic } } = req;
    // ...
    const execution = await this.executionManager.checkIfExecutionExists(executionId);
    // ↑ Only checks existence, NOT permissions/ownership
    if (!execution) { ws.close(1008); return; }
    // ...
    ws.on('message', onMessage);
    // ↑ Messages from attacker resume workflow execution
}
```

## Attack Chain

### Prerequisites
- Network access to n8n instance
- Any workflow with a Chat Trigger node is active and has a waiting execution
- Execution IDs are sequential integers (SQLite) or can be enumerated

### Steps

```
1. ENUMERATE: Try WebSocket connections to /chat?executionId=1&sessionId=x
   through /chat?executionId=N&sessionId=x until a valid execution is found.
   (Sequential integer IDs make this trivial)

2. CONNECT: WebSocket upgrade to /chat?sessionId=random&executionId=<VALID_ID>
   No cookies, no auth headers needed.

3. WAIT: Receive heartbeat message "n8n|heartbeat", respond with "n8n|heartbeat-ack"

4. INJECT: When execution is in 'waiting' status, send:
   {"action":"sendMessage","chatInput":"ATTACKER_PAYLOAD","sessionId":"random"}

5. EXECUTE: The workflow resumes with attacker's chatInput flowing through
   all downstream nodes (HTTP Request, Code, Set, etc.)
```

### Impact Scenarios

**Scenario A: Chat Session Hijacking**
An attacker connects to an active customer-facing chatbot execution and
injects malicious responses or steals conversation context.

**Scenario B: AI Prompt Injection**
The attacker's `chatInput` flows into an AI/LLM node, potentially causing
prompt injection that leaks system prompts, training data, or internal tools.

**Scenario C: Data Injection → Code Execution**
If a Code node downstream processes `$json.chatInput` without sanitization:
```javascript
// In a Code node after Chat Trigger:
const result = eval($json.chatInput); // Direct RCE
// Or more subtly:
const query = `SELECT * FROM users WHERE name = '${$json.chatInput}'`; // SQLi
```

## Affected Code Locations

| File | Line | Issue |
|------|------|-------|
| `packages/cli/src/abstract-server.ts` | ~224 | `setupPushServer()` called before auth middleware |
| `packages/cli/src/chat/chat-server.ts` | 25-37 | WS upgrade handler with no auth check |
| `packages/cli/src/chat/chat-service.ts` | 74-116 | `startSession()` with no permission check |
| `packages/cli/src/chat/chat-service.ts` | 236-240 | `resumeExecution()` resumes without auth |
| `packages/cli/src/chat/chat-execution-manager.ts` | 37-42 | `runWorkflow()` runs with injected data |

## Remediation

1. **Add authentication to the `/chat` WebSocket handler** — validate the
   auth cookie or require a signed session token in the WebSocket URL
2. **Add permission checks in `startSession()`** — verify the connecting
   user has access to the execution's workflow
3. **Consider moving ChatServer.setup() after auth middleware registration**
   to ensure all middleware runs for chat requests
4. **Use unpredictable execution IDs** for chat sessions to prevent enumeration
