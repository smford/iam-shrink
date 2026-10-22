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
echo "Example 1: Generating JSON IAM Policy from Test Suite"
echo "================================================================="
"$BIN" run -- go test -v "$DIR/..."

echo ""
echo "================================================================="
echo "Example 2: Generating Terraform Policy with Strict ARNs & Variables"
echo "================================================================="
"$BIN" run --format=tf --strict-arns --emit-vars -- go test -v "$DIR/..."

echo ""
echo "================================================================="
echo "Example 3: Generating AWS CDK (TypeScript) Construct"
echo "================================================================="
"$BIN" run --format=cdk -- go test -v "$DIR/..."
