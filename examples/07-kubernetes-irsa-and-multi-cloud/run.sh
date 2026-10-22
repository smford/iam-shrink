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
echo "1. Generating Kubernetes Deployment Manifest with CSM Sidecar"
echo "================================================================="
"$BIN" k8s manifest --deployment=order-service --namespace=production

echo ""
echo "================================================================="
echo "2. Synthesizing Kubernetes RBAC Role"
echo "================================================================="
"$BIN" run --format=k8s-rbac -- go test "$REPO_ROOT/examples/01-local-test-runner/..."

echo ""
echo "================================================================="
echo "3. Synthesizing Google Cloud IAM Custom Role (YAML)"
echo "================================================================="
"$BIN" run --format=gcp -- go test "$REPO_ROOT/examples/01-local-test-runner/..."

echo ""
echo "================================================================="
echo "4. Synthesizing Azure RBAC Custom Role (JSON)"
echo "================================================================="
"$BIN" run --format=azure -- go test "$REPO_ROOT/examples/01-local-test-runner/..."

echo ""
echo "================================================================="
echo "5. Synthesizing HashiCorp Vault AWS Secret Engine Dynamic Role"
echo "================================================================="
"$BIN" run --format=vault -- go test "$REPO_ROOT/examples/01-local-test-runner/..."
