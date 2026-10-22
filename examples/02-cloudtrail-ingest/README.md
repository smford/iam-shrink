# Example 02: Synthesizing Least-Privilege Policies from CloudTrail

This example demonstrates how `iam-shrink` processes AWS CloudTrail event logs (both uncompressed `.json` and gzip-compressed `.json.gz`) to synthesize an exact, least-privilege IAM policy based on actual historical API calls and resource ARNs.

---

## The Problem

Many production workloads have been running for years with broad, historical IAM roles (e.g. `AdministratorAccess` or wildcard `s3:*`).
- Security audits demand tightening these roles to least privilege.
- Engineering teams fear that manually stripping permissions will break production systems unexpectedly.
- Manually reading through millions of CloudTrail JSON lines to construct a JSON or Terraform policy is tedious, slow, and error-prone.

---

## How iam-shrink Solves It

The `iam-shrink ingest` command:
1. Ingests raw CloudTrail logs (individual files, directories, or compressed `.json.gz` archives).
2. Parses recorded API calls, request parameters, and referenced resource ARNs.
3. Groups statements logically by AWS service.
4. Generates standard JSON, Terraform (`--format=tf`), AWS CDK (`--format=cdk`), or other supported formats with zero wildcards where exact ARNs were recorded.

---

## Files in this Directory

* `cloudtrail_sample.json`: Realistic CloudTrail events containing S3, DynamoDB, KMS, and SQS calls with exact ARNs.
* `run.sh`: Automated demo script running `iam-shrink ingest`.

---

## Usage

Run the sample script:

```bash
./run.sh
```

Or run directly from the command line:

```bash
# Output JSON policy
iam-shrink ingest cloudtrail_sample.json

# Output Terraform HCL
iam-shrink ingest --format=tf cloudtrail_sample.json

# Ingest an entire directory of CloudTrail archives (including .gz)
iam-shrink ingest --format=tf /path/to/cloudtrail-bucket-dumps/
```
