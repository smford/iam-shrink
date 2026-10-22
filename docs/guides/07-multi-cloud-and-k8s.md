---
title: Kubernetes IRSA & Multi-Cloud Policy Translation
description: Kubernetes IRSA & Multi-Cloud Policy Translation for iam-shrink
---

[← Documentation Hub](../index.md)

# Kubernetes IRSA & Multi-Cloud Policy Translation

This guide explains how `iam-shrink` connects AWS IAM with modern cloud-native infrastructures:
1. **In-Cluster Kubernetes Telemetry:** Capturing runtime AWS operations from workloads running on Amazon EKS (using IRSA) via automated sidecars.
2. **Multi-Cloud Translation:** Translating captured AWS IAM operations into native **Google Cloud IAM Custom Roles**, **Azure RBAC Roles**, **Kubernetes RBAC Rules**, and **HashiCorp Vault Dynamic Roles**.

---

## 1. Kubernetes In-Cluster Telemetry Sidecars (`iam-shrink k8s manifest`)

When running containerized workloads on Amazon EKS using **IAM Roles for Service Accounts (IRSA)**, you can capture live production or staging operations directly inside the pod.

### Generating the Deployment Spec
```bash
iam-shrink k8s manifest \
  --deployment=order-processor \
  --namespace=production \
  --csm-port=31000
```

### Synthesized Kubernetes Manifest
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-processor
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: order-processor
  template:
    metadata:
      labels:
        app: order-processor
    spec:
      containers:
        # Main Application Workload
        - name: order-processor
          image: myorg/order-processor:v1.2.0
          env:
            - name: AWS_CSM_ENABLED
              value: "true"
            - name: AWS_CSM_PORT
              value: "31000"
            - name: AWS_CSM_HOST
              value: "127.0.0.1"

        # iam-shrink CSM Telemetry Collector Sidecar
        - name: iam-shrink-collector
          image: ghcr.io/smford/iam-shrink:latest
          args:
            - "session"
            - "start"
          ports:
            - containerPort: 31000
              protocol: UDP
```

Because containers in the same Kubernetes pod share the loopback network (`127.0.0.1`), the application container seamlessly streams telemetry datagrams to the `iam-shrink` collector sidecar.

---

## 2. Multi-Cloud & Cross-Cloud Translation

When migrating microservices to Google Cloud, Microsoft Azure, or Kubernetes, manually rewriting IAM permission definitions requires deep domain expertise in each cloud provider's authorization model. `iam-shrink` maps observed operations on-the-fly:

### Google Cloud Platform (GCP) IAM Custom Roles (`--format=gcp`)
```bash
iam-shrink run --format=gcp -- pytest tests/
```

*Generated YAML:*
```yaml
title: iam_shrink_least_privilege_role
description: Least-privilege role synthesized by iam-shrink
stage: GA
includedPermissions:
    - cloudkms.cryptoKeyVersions.useToDecrypt
    - spanner.databases.read
    - storage.objects.get
    - storage.objects.list
```

### Microsoft Azure RBAC Custom Roles (`--format=azure`)
```bash
iam-shrink run --format=azure -- npm test
```

*Generated JSON:*
```json
{
  "Name": "iam-shrink-least-privilege",
  "IsCustom": true,
  "Description": "Least-privilege role synthesized by iam-shrink",
  "Actions": [
    "Microsoft.DocumentDB/databaseAccounts/read",
    "Microsoft.KeyVault/vaults/keys/decrypt/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/${var.subscription_id}"
  ]
}
```

### Kubernetes RBAC (`--format=k8s-rbac`)
```bash
iam-shrink run --format=k8s-rbac -- go test ./...
```

*Generated YAML:*
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: iam-shrink-least-privilege
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["s3"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["dynamodb"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["kms"]
    verbs: ["get"]
```

### HashiCorp Vault Dynamic AWS Secrets (`--format=vault`)
```bash
iam-shrink run --format=vault -- pytest tests/
```

*Generated Script:*
```bash
# HashiCorp Vault AWS Secret Engine Role Configuration:
vault write aws/roles/least-privilege-app \
    credential_type=assumed_role \
    role_arn="arn:aws:iam::${var.account_id}:role/AppRole" \
    policy_document=@- <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPolicyActions",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query",
        "kms:Decrypt",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": ["*"]
    }
  ]
}
EOF
```

---

**Navigation:** [← Previous: Terraform & OpenTofu](03-terraform-and-opentofu.md) | [Next: Legacy Role Pruning SOP →](04-legacy-role-pruning-runbook.md)
