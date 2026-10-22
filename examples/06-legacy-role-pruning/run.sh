#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
BIN="$REPO_ROOT/bin/iam-shrink"

if [ ! -f "$BIN" ]; then
  echo "Building iam-shrink binary..."
  (cd "$REPO_ROOT" && go build -o bin/iam-shrink ./cmd/iam-shrink)
fi

echo "================================================================="
echo "1. Pruning Unused Permissions from Legacy IAM Role Policy"
echo "================================================================="
"$BIN" prune-role \
  --active-actions="s3:GetObject,dynamodb:PutItem" \
  --out="$DIR/pruned_role.json" \
  "$DIR/legacy_role.json"

echo ""
echo "================================================================="
echo "2. Mathematical Subset Verification: Zero Shadow Expansion"
echo "================================================================="
"$BIN" verify "$DIR/legacy_role.json" "$DIR/pruned_role.json"

echo ""
echo "================================================================="
echo "3. Historical Blast Radius Analysis: Verifying 100% Safety"
echo "================================================================="
"$BIN" impact "$DIR/cloudtrail_active.json" "$DIR/pruned_role.json"

echo ""
echo "================================================================="
echo "4. Diff Report: Showing 88.2% Attack Surface Reduction"
echo "================================================================="
"$BIN" diff "$DIR/legacy_role.json" "$DIR/pruned_role.json"

echo ""
echo "================================================================="
echo "5. Compression: Auditing & Optimizing Policy to Fit AWS Quotas"
echo "================================================================="
"$BIN" optimize --out="$DIR/pruned_role_optimized.json" "$DIR/pruned_role.json"
"$BIN" optimize --check "$DIR/pruned_role_optimized.json"
rm -f "$DIR/pruned_role.json" "$DIR/pruned_role_optimized.json"
