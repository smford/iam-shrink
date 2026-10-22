# iam-shrink

**Local-to-Least-Privilege AWS IAM Policy Generator**

> Intercept AWS operations during local test suites, scripts, or deployment dry runs and automatically synthesize exact, least-privilege IAM policies.

---

## 💡 What is iam-shrink? (In Simple Terms)

When developers write code that talks to AWS (like reading from an S3 bucket or saving to DynamoDB), they usually do not know the exact list of obscure AWS IAM action names and ARNs required.

Because getting "Access Denied" errors slows down development, developers and teams routinely slap on `AdministratorAccess` or broad wildcard policies (`Action: "*", Resource: "*"`). These over-privileged policies make it into staging and production, exposing organizations to massive data breaches, privilege escalation, and compliance audit failures.

**`iam-shrink` solves this automatically.**

It acts like a transparent observer. When you run your existing test suite (e.g. `go test`, `pytest`, `npm test`, or `terraform plan`), `iam-shrink` quietly watches every AWS call your code makes in real time. It then writes the **exact, minimal security policy** needed to run your application—formatted in **Terraform HCL**, **AWS CDK**, **CDKTF**, **Pulumi**, **CloudFormation**, **AWS Identity Center (SSO)**, **GCP IAM**, **Azure RBAC**, **Kubernetes RBAC**, or **JSON**.

---

## 🎯 The Core Problems iam-shrink Solves

| The Problem | How iam-shrink Solves It |
|---|---|
| **1. The "Wildcard Trap"**<br>Developers grant `*` permissions because AWS has 14,000+ IAM actions and figuring out exact permissions takes hours of trial and error. | **Zero-effort capture**: Runs alongside your local tests with zero code changes, recording exact APIs called and emitting least-privilege policies in seconds. |
| **2. The CloudTrail Delay**<br>Traditional policy generators require deploying code to an AWS account and waiting 15–30 minutes (or days) for CloudTrail logs to aggregate. | **Instant local interception**: Uses AWS Client-Side Monitoring (CSM) and local proxying on `127.0.0.1`. You get your policy the millisecond your test suite completes. |
| **3. The "Production Breaking" Fear**<br>DevOps teams are terrified of shrinking permissions because removing permissions might break rare operations (e.g. month-end cron jobs, disaster recovery drills). | **Historical Blast Radius Scoring (`iam-shrink impact`)**: Cross-references proposed policies against 30/60/90 days of CloudTrail logs, scoring safety and pinpointing rare calls that would be severed. |
| **4. Hard AWS Byte Limits**<br>AWS enforces strict quotas on policy sizes (max **2,048 bytes** for inline policies, **10,240 bytes** for managed policies). Complex apps breach these limits. | **Automatic Compression (`iam-shrink optimize`)**: Merges statements sharing resource targets and minifies JSON to compress byte size by up to 30–50%. |
| **5. Multi-Cloud & Multi-IaC Tower of Babel**<br>Modern organizations use Terraform, CDK, AWS SSO, Google Cloud, Azure, and Kubernetes. Manually rewriting IAM across all these syntaxes is painful. | **One-click Multi-Format Export**: Generates native Terraform HCL, AWS CDK, Pulumi, CloudFormation, AWS SSO Permission Sets, GCP IAM Custom Roles, Azure RBAC, and K8s RBAC. |
| **6. Stale Compliance & Audit Drift**<br>Auditing against CIS AWS Benchmark v3.0 and NIST SP 800-53 usually requires expensive external scanners and manual spreadsheets. | **Built-in Compliance & Live Sync (`iam-shrink report` & `update-rules`)**: Audits policies locally and automatically syncs updated benchmarks every week via GitHub Actions. |

---

## 🚀 Installation

### Via Homebrew (macOS & Linux)
```bash
brew install smford/tap/iam-shrink
```

### Via Docker Container (Zero-Install)
```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ghcr.io/smford/iam-shrink:latest run --format=tf -- pytest tests/
```

### From Source (Go 1.23+)
```bash
git clone https://github.com/smford/iam-shrink.git
cd iam-shrink
make build
# Binary created at ./bin/iam-shrink
```

### Direct Go Install
```bash
go install github.com/smford/iam-shrink/cmd/iam-shrink@latest
```

---

## 🛠️ Complete Feature Guide & Problem Explanations

Each feature in `iam-shrink` was built to solve a specific, real-world security or operational problem:

---

### 1. Dual Interception Engine (CSM & MITM Proxy)

* **The Problem:** AWS SDK calls transmit service names (like `S3`) and operation names (like `GetObject`), but standard telemetry often omits the exact target resource ARN (e.g. `arn:aws:s3:::my-production-bucket/keys/*`).
* **How iam-shrink Solves It:**
  1. **AWS CSM (Client-Side Monitoring):** A lightweight UDP daemon listening on `127.0.0.1` that standard AWS SDKs natively broadcast to when `AWS_CSM_ENABLED=true` is set.
  2. **HTTP/HTTPS Interception Proxy (`--proxy`):** Spawns an ephemeral local CA proxy that inspects outgoing API request paths and parameters on-the-fly, extracting exact table names, bucket ARNs, and KMS key IDs.

```bash
# Capture with exact runtime ARNs via proxy
iam-shrink run --proxy --format=tf -- go test ./...
```

---

### 2. AWS Identity Center (AWS SSO) Permission Sets (`--format=sso`)

* **The Problem:** Modern multi-account AWS Organizations do not assign raw IAM roles directly to humans. They use **AWS Identity Center Permission Sets**, which have specific Terraform syntax (`aws_ssoadmin_permission_set`, `aws_ssoadmin_permission_set_inline_policy`, session durations).
* **How iam-shrink Solves It:** `--format=sso` synthesizes turnkey Terraform HCL for Identity Center with custom session durations (e.g. `PT4H`).

```bash
iam-shrink run --format=sso --session-duration="PT4H" -- pytest tests/
```

---

### 3. Historical Blast Radius & Operational Risk Scoring (`iam-shrink impact`)

* **The Problem:** When replacing a wide policy with a shrunk policy, nobody knows if an un-tested, infrequent operation (like a monthly backup or quarterly disaster recovery drill) will be blocked and cause an outage.
* **How iam-shrink Solves It:** `iam-shrink impact` reads historical CloudTrail logs, compares every single recorded event against the proposed shrunk policy, calculates an **Operational Safety Score**, and warns you of any rare calls that would be severed.

```bash
# Analyze impact against historical CloudTrail logs
iam-shrink impact /var/log/cloudtrail/ proposed_shrunk_policy.json

# Fail CI if safety score is below 99% or if any call is severed
iam-shrink impact --min-score=99.0 --fail-on-severed /path/to/logs/ policy.json
```

---

### 4. Trace-to-Code Policy Annotator (`--annotate`)

* **The Problem:** When a security auditor reviews a generated IAM policy, they demand to know: *"Why does this service need `dynamodb:DeleteItem`? Which file and function called it?"*
* **How iam-shrink Solves It:** Passing `--annotate` injects code provenance and access-level comments directly above each statement in Terraform and JSON.

```bash
iam-shrink run --annotate --format=tf -- go test ./...
```
*Generated output:*
```hcl
statement {
  sid    = "DynamoDBWrite"
  effect = "Allow"
  actions = [
    # observed runtime SDK call for dynamodb:PutItem (AccessLevel: Write)
    "dynamodb:PutItem",
  ]
  resources = ["arn:aws:dynamodb:us-east-1:123456789012:table/Orders"]
}
```

---

### 5. Formal Subset & Equivalence Verification (`iam-shrink verify`)

* **The Problem:** When rewriting or pruning a policy, it is easy to accidentally introduce "shadow expansions" (e.g. adding a wildcard that unknowingly grants dangerous unintended permissions).
* **How iam-shrink Solves It:** `iam-shrink verify` mathematically evaluates whether the shrunk policy is a strict subset of the base policy. If any ungranted permissions or wildcard escalations exist, it fails with exit code `1` and highlights the exact discrepancy.

```bash
iam-shrink verify production_base.json shrunk_policy.json
```

---

### 6. Policy Size Compression & Quota Optimization (`iam-shrink optimize`)

* **The Problem:** AWS enforces hard limits: **2,048 bytes** for inline policies and **10,240 bytes** for managed policies. Large microservices frequently exceed this limit.
* **How iam-shrink Solves It:** `iam-shrink optimize` groups statements with identical resources, strips redundant prefixes, minifies JSON, and audits byte count against AWS limits.

```bash
# Audit policy size against inline and managed quotas
iam-shrink optimize --check policy.json

# Minify and save
iam-shrink optimize --out=compressed_policy.json policy.json
```

---

### 7. Multi-Cloud IAM & RBAC Translation (`--format=gcp|azure|k8s-rbac|vault`)

* **The Problem:** Multi-cloud teams build applications spanning AWS, GCP, Azure, and Kubernetes. Translating an AWS permission model to GCP Custom Roles or Azure RBAC requires deep specialized expertise across all cloud providers.
* **How iam-shrink Solves It:** `iam-shrink` translates captured AWS actions directly into equivalent permissions for other clouds:
  - **GCP Custom Roles (`--format=gcp`):** e.g., `s3:GetObject` $\rightarrow$ `storage.objects.get`.
  - **Azure RBAC (`--format=azure`):** e.g., `s3:GetObject` $\rightarrow$ `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`.
  - **Kubernetes RBAC (`--format=k8s-rbac`):** Maps to `ClusterRole` verbs and apiGroups.
  - **HashiCorp Vault (`--format=vault`):** Outputs Vault AWS Secret Engine dynamic role commands.

```bash
iam-shrink run --format=gcp -- pytest tests/
iam-shrink run --format=azure -- npm test
iam-shrink run --format=k8s-rbac -- go test ./...
```

---

### 8. CIS AWS Foundations & NIST SP 800-53 Compliance Reporting

* **The Problem:** Compliance standards (CIS Benchmark v3.0, NIST SP 800-53 Rev 5) are huge documents. Auditing policies against them is usually done retroactively after security failures.
* **How iam-shrink Solves It:**
  - `iam-shrink report`: Audits policies in the terminal or generates markdown tables with pass/fail badges.
  - `iam-shrink update-rules`: Fetches updated benchmark schemas.
  - An automated GitHub Action (`compliance-sync.yml`) runs weekly, parsing upstream catalogs and keeping the repository's embedded rules fresh.

```bash
# Audit policy against CIS AWS Foundations Benchmark
iam-shrink report --standard=cis policy.json

# Audit policy against NIST SP 800-53 Rev 5 in Markdown format
iam-shrink report --standard=nist --format=markdown policy.json
```

---

### 9. CI/CD Quality Gate & Automated PR Commenter

* **The Problem:** Security teams cannot manually review every pull request that modifies IAM permissions.
* **How iam-shrink Solves It:**
  - `iam-shrink gate`: Blocks CI builds if wildcards (`*`) or high-severity compliance violations are introduced.
  - `iam-shrink pr-comment`: Automatically posts a formatted Markdown review comment to GitHub PRs showing permissions added/removed and compliance scores.

```bash
# Enforce CI Quality Gate (fail on wildcards or <90% compliance)
iam-shrink gate --fail-on-wildcard --min-compliance=90.0 policy.json

# Generate PR comment
iam-shrink pr-comment --existing=base_role.json --captured=new_policy.json --standard=cis
```

---

### 10. In-Place Terraform Patching (`iam-shrink patch`)

* **The Problem:** Copying and pasting generated policies from terminal output into Terraform files is tedious and error-prone.
* **How iam-shrink Solves It:** `iam-shrink patch` executes your test suite and automatically locates and replaces the `data "aws_iam_policy_document"` block in your `.tf` file in-place, creating an automatic backup (`.tf.bak`).

```bash
iam-shrink patch --file=infrastructure/iam.tf -- go test ./...
```

---

### 11. OpenTofu & Terraform State Resolution (`iam-shrink state`)

* **The Problem:** Static code generates parameterized placeholders (`arn:aws:s3:::${var.bucket_name}`), but deployed policies need exact resource ARNs.
* **How iam-shrink Solves It:** `iam-shrink state` parses `terraform.tfstate`, matches variable placeholders against real deployed cloud resources, and substitutes concrete ARNs.

```bash
iam-shrink state terraform.tfstate policy.json
```

---

### 12. Interactive Single-Page Web UI (`iam-shrink ui`)

* **The Problem:** Visualizing complex IAM policies in raw JSON or HCL is difficult for non-security specialists.
* **How iam-shrink Solves It:** Spawns a zero-dependency, local web application on `127.0.0.1:8080`. Offers live permission toggles, access-level filtering, and real-time code preview tabs across Terraform, CDK, GCP, Azure, K8s, and Vault.

```bash
iam-shrink ui --port=8080 policy.json
```

---

### 13. Zero-Install Official Container Image

* **The Problem:** Installing Go or compiling binaries inside diverse CI/CD environments (Node.js, Python, Java) adds build friction.
* **How iam-shrink Solves It:** The multi-arch Docker image (`ghcr.io/smford/iam-shrink:latest`) packages `iam-shrink` with pre-configured CSM telemetry listeners.

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ghcr.io/smford/iam-shrink:latest run --format=tf -- npm test
```

---

### 14. Turnkey Composite GitHub Action (`action.yml`)

* **The Problem:** Configuring GitHub Actions workflows with manual binary downloads and UDP networking is complex.
* **How iam-shrink Solves It:** A single composite step in your GitHub Actions workflow:

```yaml
name: IAM Least Privilege Check
on: [pull_request]

jobs:
  least-privilege:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: smford/iam-shrink@main
        with:
          command: 'go test -v ./...'
          format: 'tf'
          out: 'policy.tf'
          strict-arns: 'true'
          compliance: 'cis'
```

---

### 15. Daemon / Background Session Mode (`iam-shrink session`)

* **The Problem:** Test suites split across multiple commands, Docker Compose containers, or background dev servers cannot use a single `iam-shrink run -- <cmd>` invocation.
* **How iam-shrink Solves It:** `iam-shrink session start` launches a background collector daemon. Multiple containers or test scripts broadcast to it, and `iam-shrink session dump` aggregates all calls into one unified policy.

```bash
iam-shrink session start
# export AWS_CSM_ENABLED=true ...
pytest tests/
npm run test:integration
iam-shrink session dump --format=tf
iam-shrink session stop
```

---

## 💻 CLI Command Reference

```text
Usage:
  iam-shrink run [flags] -- <command> [args...]
  iam-shrink ingest [flags] <cloudtrail-file-or-dir>
  iam-shrink patch --file=<main.tf> [flags] -- <command> [args...]
  iam-shrink prune-role <role-policy.json> [flags]
  iam-shrink verify <base-policy.json> <shrunk-policy.json>
  iam-shrink optimize [flags] <policy.json>
  iam-shrink impact [flags] <cloudtrail-file-or-dir> <policy.json>
  iam-shrink report [flags] <policy.json>
  iam-shrink update-rules [flags]
  iam-shrink state <terraform.tfstate> [policy.json]
  iam-shrink pr-comment [flags]
  iam-shrink gate [flags] <policy.json>
  iam-shrink ui [flags] [policy.json]
  iam-shrink diff <existing-policy.json> [captured-policy.json]
  iam-shrink lint <policy.json>
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink k8s manifest [flags]
  iam-shrink init-vscode [flags]
  iam-shrink session <start|status|dump|stop> [flags]
  iam-shrink version
```

---

## 🧪 Development & Testing

```bash
# Run all unit and integration tests (zero-CGO)
make test

# Run Go static analysis
make vet

# Build binary locally
make build
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
