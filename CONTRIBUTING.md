# Contributing to iam-shrink

Thank you for your interest in contributing to `iam-shrink`! We appreciate contributions of all kinds: bug fixes, new output formats, updated AWS SDK action mappings, performance improvements, documentation, and tutorials.

---

## Architecture Overview

`iam-shrink` is designed as a modular, zero-CGO Go application. Key internal packages:

```text
cmd/
  iam-shrink/           # Main CLI entrypoint and subcommand dispatch
internal/
  csm/                  # AWS Client-Side Monitoring loopback UDP listener
  proxy/                # Ephemeral HTTP/HTTPS MITM proxy for runtime ARN inspection
  mapper/               # Embedded database mapping AWS SDK operations to IAM actions & ARNs
  advisor/              # IAM role policy pruning and unused permission calculation
  render/               # Policy synthesis (JSON, Terraform HCL, CDK, CDKTF, Pulumi, CFN, SSO)
  multicloud/           # Cross-cloud translation (GCP Custom Roles, Azure RBAC, K8s RBAC, Vault)
  verifier/             # Mathematical subset and shadow expansion analysis
  impact/               # Historical CloudTrail blast radius and severed call risk calculator
  compliance/           # CIS AWS Foundations Benchmark & NIST SP 800-53 evaluation
  optimizer/            # Policy minification and statement merging under AWS byte quotas
  linter/               # Static privilege escalation and security risk detector
  webui/                # Interactive zero-dependency local web visualizer
```

---

## Local Development Workflow

### Prerequisites
* **Go 1.23+**
* `make`
* `git`

### Building & Running Tests
```bash
# Clone the repository
git clone https://github.com/smford/iam-shrink.git
cd iam-shrink

# Run all unit and integration tests (zero CGO required)
make test

# Run Go static analysis
make vet

# Build local binary (placed in bin/iam-shrink)
make build
```

---

## Adding or Updating AWS SDK Action Mappings

The mapping database lives in [`internal/mapper/`](internal/mapper/).

1. Check current mapping using the CLI:
   ```bash
   iam-shrink explain Bedrock:InvokeModel
   ```
2. If an AWS service or operation is missing or requires more specific ARN templates, edit `internal/mapper/mapper.go`.
3. Add corresponding unit tests in `internal/mapper/mapper_test.go`.
4. Run `make test` to verify.

---

## Adding a New Output Format

To add a new IaC or cloud format (e.g. Bicep, Crossplane):
1. Add the format type in `internal/render/render.go` or `internal/multicloud/multicloud.go`.
2. Implement the renderer function taking `[]ActionItem` and returning formatted output.
3. Wire the format flag in `cmd/iam-shrink/main.go` and `internal/runner/runner.go`.
4. Add unit test coverage and an example in `examples/`.

---

## Coding Standards

* **Zero CGO**: The project must build with `CGO_ENABLED=0` across Linux, macOS, and Windows.
* **Deterministic Output**: Formatted policies should sort statements and actions deterministically to prevent git diff churn.
* **Preserve Backward Compatibility**: CLI flags and subcommands must remain backward-compatible across minor semver releases.
* **Pre-commit Hooks**: We use standard pre-commit hooks (`golangci-lint`, `shellcheck`, etc.).

---

## Submitting Pull Requests

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feat/my-awesome-feature
   ```
2. Make your changes and ensure all tests pass:
   ```bash
   make test
   make vet
   ```
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   * `feat: add Bicep output format support`
   * `fix: correct KMS decrypt ARN pattern`
   * `docs: update worked examples for Python`
4. Push to your fork and submit a Pull Request!
