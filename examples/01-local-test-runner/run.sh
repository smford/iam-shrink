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
echo "1. Go Test Suite -> JSON Policy"
echo "================================================================="
"$BIN" run -- go test -v "$DIR/..."

echo ""
echo "================================================================="
echo "2. Python Test Suite (pytest/python3) -> Terraform HCL + Variables"
echo "================================================================="
"$BIN" run --format=tf --strict-arns --emit-vars -- python3 "$DIR/test_app.py"

echo ""
echo "================================================================="
echo "3. Node.js Test Suite -> AWS CDK (TypeScript)"
echo "================================================================="
"$BIN" run --format=cdk -- node "$DIR/app.test.js"

echo ""
echo "================================================================="
echo "4. Multi-Cloud Translation -> GCP IAM Custom Role YAML"
echo "================================================================="
"$BIN" run --format=gcp -- go test "$DIR/..."
