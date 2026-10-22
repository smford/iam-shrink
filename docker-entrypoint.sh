#!/bin/bash
set -e

# If first arg is a known subcommand, flag, or empty, run iam-shrink directly
case "$1" in
  run|ingest|verify|optimize|impact|report|update-rules|gate|pr-comment|diff|lint|ui|state|patch|prune-role|explain|export-mappings|k8s|init-vscode|session|license|version|help|-*|"")
    exec /usr/local/bin/iam-shrink "$@"
    ;;
  *)
    # Otherwise treat arguments as child command to run under iam-shrink
    exec /usr/local/bin/iam-shrink run -- "$@"
    ;;
esac
