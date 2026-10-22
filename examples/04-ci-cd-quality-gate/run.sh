#!/bin/bash
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
BIN="$REPO_ROOT/bin/iam-shrink"

if [ ! -f "$BIN" ]; then
  echo "Building iam-shrink binary..."
  (cd "$REPO_ROOT" && go build -o bin/iam-shrink ./cmd/iam-shrink)
fi

echo "================================================================="
echo "1. Security Linter: Detecting Privilege Escalation on Insecure Policy"
echo "================================================================="
"$BIN" lint "$DIR/insecure_policy.json" || true

echo ""
echo "================================================================="
echo "2. CI/CD Gate: Blocking on Insecure Policy (--fail-on-wildcard)"
echo "================================================================="
if "$BIN" gate --fail-on-wildcard "$DIR/insecure_policy.json"; then
  echo "ERROR: Gate should have failed!"
  exit 1
else
  echo "[EXPECTED] Gate correctly failed and blocked CI/CD build on wildcards."
fi

echo ""
echo "================================================================="
echo "3. CI/CD Gate: Verifying Compliant Policy Passes All Quality Checks"
echo "================================================================="
"$BIN" gate --fail-on-wildcard --standard=cis "$DIR/compliant_policy.json"
echo "[SUCCESS] Compliant policy passed all security gates."

echo ""
echo "================================================================="
echo "4. Compliance Audit: Auditing Compliant Policy against CIS Benchmark"
echo "================================================================="
"$BIN" report --standard=cis "$DIR/compliant_policy.json"

echo ""
echo "================================================================="
echo "5. PR Comment Generator: Generating Markdown for Pull Request Review"
echo "================================================================="
"$BIN" pr-comment --existing="$DIR/insecure_policy.json" --captured="$DIR/compliant_policy.json" --standard=cis
