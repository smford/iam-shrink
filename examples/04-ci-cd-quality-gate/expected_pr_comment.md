## 🛡️ `iam-shrink` Least-Privilege & Compliance Analysis

📉 Reduced Permission Attack Surface by **100.0%**

<details>
<summary><b>📊 Permission Diff (Click to expand)</b></summary>

- **Existing Actions:** 2
- **Runtime Actions Exercised:** 3
- **Retained Actions:** 0
- **Unused Permissions (Pruned):** 2
- **Missing Permissions (Added):** 3

```diff
# Unused Permissions Recommended for Pruning:
- iam:CreatePolicyVersion
- s3:*
```
```diff
# Required Permissions Observed at Runtime:
+ dynamodb:GetItem
+ dynamodb:PutItem
+ s3:GetObject
```
</details>

### 🛡️ Compliance Audit: CIS AWS Foundations Benchmark (v3.0.0) — 🟢 Compliant

**Compliance Score:** `100.0%` (4/4 checks passed)

| Control | Severity | Status | Details |
| :--- | :--- | :---: | :--- |
| **1.16** Ensure IAM policies that allow full "*:*" administrative privileges are not attached | `CRITICAL` | ✅ PASS | - |
| **1.20** Ensure iam:PassRole access is not granted on wildcard resource '*' | `HIGH` | ✅ PASS | - |
| **1.21** Ensure sts:AssumeRole access is not granted on wildcard resource '*' | `HIGH` | ✅ PASS | - |
| **1.22** Ensure service-level wildcard actions are not used | `MEDIUM` | ✅ PASS | - |


_Generated automatically by [iam-shrink](https://github.com/smford/iam-shrink)_ 🚀
