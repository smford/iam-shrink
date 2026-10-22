#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
BIN="$REPO_ROOT/bin/iam-shrink"

if [ ! -f "$BIN" ]; then
  echo "Building iam-shrink binary..."
  (cd "$REPO_ROOT" && go build -o bin/iam-shrink ./cmd/iam-shrink)
fi

# Reset main.tf to initial state if a previous run patched it
cat << 'EOF' > "$DIR/main.tf"
provider "aws" {
  region = "us-east-1"
}

# Insecure placeholder policy containing broad wildcards:
data "aws_iam_policy_document" "app_policy" {
  statement {
    sid       = "WildcardAdminAccess"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "app_exec" {
  name   = "microservice-execution-policy"
  policy = data.aws_iam_policy_document.app_policy.json
}
EOF

echo "================================================================="
echo "Original main.tf (Over-permissive wildcard policy):"
echo "================================================================="
cat "$DIR/main.tf"

echo ""
echo "================================================================="
echo "Executing iam-shrink patch to update main.tf in-place"
echo "================================================================="
"$BIN" patch --file="$DIR/main.tf" -- go run "$DIR/mock_service.go"

echo ""
echo "================================================================="
echo "Patched main.tf (Synthesized least-privilege policy):"
echo "================================================================="
cat "$DIR/main.tf"

echo ""
echo "================================================================="
echo "Diff showing in-place replacement:"
echo "================================================================="
diff -u "$DIR/main.tf.bak" "$DIR/main.tf" || true
