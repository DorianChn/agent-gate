#!/usr/bin/env bash
# agent-gate CLI walkthrough.
#
# Usage:  PYTHON=/path/to/python3 bash demo_cli.sh
# (defaults to `python3` on PATH)

set -u
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
AUDIT="./.demo_audit.jsonl"
rm -f "$AUDIT"
GATE=("$PY" -m agent_gate.cli)

echo "== agent-gate CLI demo (audit log: $AUDIT)"
echo

echo "### 1. Allowed call: researcher reads a file under /tmp"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --role researcher --tool file_read \
  --params '{"path": "/tmp/report.txt", "max_bytes": 100}'
echo

echo "### 2. Denied: researcher tries to read /etc/passwd (path pattern)"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --role researcher --tool file_read --params '{"path": "/etc/passwd"}'
echo

echo "### 3. Denied: researcher calls a tool outside its role (file_write)"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --role researcher --tool file_write --params '{"path": "/tmp/x.txt", "content": "hi"}'
echo

echo "### 4. Denied: editor writes outside /workspace (path pattern)"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --role editor --tool file_write --params '{"path": "/tmp/x.txt", "content": "hi"}'
echo

echo "### 5. Denied: editor payload exceeds max_length (read from file)"
BIG=$(printf 'a%.0s' $(seq 1 70000))
echo "{\"path\": \"/workspace/x.txt\", \"content\": \"$BIG\"}" > "$AUDIT.params.json"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --role editor --tool file_write --params-file "$AUDIT.params.json"
rm -f "$AUDIT.params.json"
echo

echo "### 6. Credential lifecycle: issue -> verify -> expire"
TOKEN=$("${GATE[@]}" token-issue --secret demo-secret --role researcher \
  --scope "file_read,web_*" --ttl 300 | "$PY" -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "issued token: ${TOKEN:0:32}..."
"${GATE[@]}" token-verify --secret demo-secret --token "$TOKEN"
SHORT=$("${GATE[@]}" token-issue --secret demo-secret --role researcher \
  --scope "file_read" --ttl 1 | "$PY" -c "import sys,json;print(json.load(sys.stdin)['token'])")
sleep 2
echo "after 2s, a 1s-TTL token:"
"${GATE[@]}" token-verify --secret demo-secret --token "$SHORT" || true
echo

echo "### 7. Token scope: researcher's credential only covers file_read,web_*"
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --token "$TOKEN" --tool file_read --params '{"path": "/tmp/report.txt"}'
"${GATE[@]}" check --policy examples/policy.json --secret demo-secret --audit "$AUDIT" \
  --token "$TOKEN" --tool file_write --params '{"path": "/workspace/x.txt", "content": "hi"}'
echo

echo "### 8. Audit trail (every decision above is recorded, secrets masked)"
"${GATE[@]}" audit --log "$AUDIT" --limit 5
echo

echo "done."
