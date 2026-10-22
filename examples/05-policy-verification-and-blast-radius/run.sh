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
echo "1. Mathematical Subset Verification: Valid Shrunk Policy"
echo "================================================================="
"$BIN" verify "$DIR/base_policy.json" "$DIR/candidate_policy.json"

echo ""
echo "================================================================="
echo "2. Mathematical Subset Verification: Detecting Illegal Permission Expansion"
echo "================================================================="
if "$BIN" verify "$DIR/base_policy.json" "$DIR/violating_policy.json"; then
  echo "ERROR: Should have detected expansion!"
  exit 1
else
  echo "[EXPECTED] Verifier successfully blocked illegal privilege expansion."
fi

echo ""
echo "================================================================="
echo "3. Historical Blast Radius Analysis: Evaluating Operational Risk"
echo "================================================================="
"$BIN" impact "$DIR/historical_cloudtrail.json" "$DIR/candidate_policy.json" || true
echo "[SUCCESS] Blast radius analysis completed."
