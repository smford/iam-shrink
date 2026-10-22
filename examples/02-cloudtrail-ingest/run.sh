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
echo "Ingesting CloudTrail JSON to Synthesize Least-Privilege Policy"
echo "================================================================="
"$BIN" ingest "$DIR/cloudtrail_sample.json"

echo ""
echo "================================================================="
echo "Ingesting and Outputting Directly to Terraform HCL"
echo "================================================================="
"$BIN" ingest --format=tf "$DIR/cloudtrail_sample.json"
