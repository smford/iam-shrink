# Example 07: Kubernetes IRSA & Multi-Cloud Policy Translation

This worked example demonstrates how `iam-shrink` Bridges AWS IAM with modern cloud-native architectures:
1. **Kubernetes In-Cluster Observation:** Automatically generates Pod spec sidecars (`iam-shrink k8s manifest`) that collect AWS CSM telemetry from containerized workloads in real time.
2. **Multi-Cloud Translation:** Automatically translates captured AWS operations into equivalent permissions for **Kubernetes RBAC**, **Google Cloud IAM Custom Roles**, **Azure RBAC Custom Roles**, and **HashiCorp Vault AWS Secret Engine** configurations.

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`expected_k8s_deployment.yaml`](expected_k8s_deployment.yaml) | Kubernetes Deployment manifest configured with the `iam-shrink` CSM telemetry sidecar. |
| [`expected_k8s_role.yaml`](expected_k8s_role.yaml) | Equivalent Kubernetes RBAC `Role` synthesized from observed runtime calls. |
| [`expected_gcp_role.yaml`](expected_gcp_role.yaml) | Google Cloud IAM Custom Role YAML (`stage: GA`) mapping AWS permissions to GCP. |
| [`expected_azure_role.json`](expected_azure_role.json) | Azure RBAC Custom Role JSON mapping AWS operations to Azure Provider actions. |
| [`expected_vault_role.sh`](expected_vault_role.sh) | Turnkey HashiCorp Vault CLI script to write dynamic AWS assumed roles. |
| [`run.sh`](run.sh) | Standalone script demonstrating manifest generation and multi-cloud synthesis. |

---

## 1. Kubernetes Sidecar Manifest Generation

To capture IAM telemetry from applications running inside Kubernetes (such as EKS with IRSA), generate a sidecar deployment spec:

```bash
iam-shrink k8s manifest --deployment=order-service --namespace=production
```

This injects:
* `AWS_CSM_ENABLED=true` and `AWS_CSM_PORT=31000` into your application container.
* The `iam-shrink` collector daemon sidecar on port `31000/UDP`.

---

## 2. Cross-Cloud Permission Translation

Modern microservices frequently migrate between clouds or share architectural patterns. `iam-shrink` translates observed operations on-the-fly:

### Google Cloud IAM Custom Role (`--format=gcp`)
```bash
iam-shrink run --format=gcp -- pytest tests/
```
Translates `s3:GetObject` and `s3:ListBucket` to `storage.objects.get` and `storage.objects.list`, and `dynamodb:Query` to `spanner.databases.read`.

### Azure RBAC Custom Role (`--format=azure`)
```bash
iam-shrink run --format=azure -- pytest tests/
```
Translates AWS S3 calls to `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`.

### Kubernetes RBAC (`--format=k8s-rbac`)
```bash
iam-shrink run --format=k8s-rbac -- pytest tests/
```
Generates standard Kubernetes RBAC `Role` rules with appropriate verbs and resource mappings.

### HashiCorp Vault (`--format=vault`)
```bash
iam-shrink run --format=vault -- pytest tests/
```
Generates a complete `vault write aws/roles/...` command with the embedded least-privilege policy.

---

## Running the Example

```bash
./examples/07-kubernetes-irsa-and-multi-cloud/run.sh
```
