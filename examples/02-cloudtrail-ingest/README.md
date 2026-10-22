# Example 02: CloudTrail Log Ingestion

This worked example demonstrates how `iam-shrink` processes historical AWS CloudTrail audit logs (`.json` or `.json.gz`) to automatically synthesize least-privilege policies based on real observed production traffic.

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`cloudtrail_sample.json`](cloudtrail_sample.json) | Sample CloudTrail event log containing recorded AWS S3 and DynamoDB calls. |
| [`expected_policy.json`](expected_policy.json) | The exact IAM JSON policy synthesized from the CloudTrail log. |
| [`expected_policy.tf`](expected_policy.tf) | Terraform HCL with parameterized ARNs synthesized from CloudTrail. |
| [`run.sh`](run.sh) | Runnable shell script executing ingestion in both JSON and Terraform formats. |

---

## Running the Example

Run the automated script:
```bash
./examples/02-cloudtrail-ingest/run.sh
```

Or run manually:

```bash
# Ingest single CloudTrail file
iam-shrink ingest examples/02-cloudtrail-ingest/cloudtrail_sample.json

# Ingest and output Terraform HCL with strict ARNs
iam-shrink ingest --format=tf --strict-arns examples/02-cloudtrail-ingest/cloudtrail_sample.json

# Ingest an entire directory of compressed CloudTrail logs
iam-shrink ingest /var/log/cloudtrail/
```

---

## Pre-Committed Outputs

* [expected_policy.json](expected_policy.json) — Synthesized AWS IAM JSON policy.
* [expected_policy.tf](expected_policy.tf) — Synthesized Terraform `data "aws_iam_policy_document"` block.
