# CloudPathX — Shift-Left Infrastructure as Code (IaC) Scanner

**Module:** `backend/app/engine.py` (`scan_iac`)  
**API Endpoint:** `POST /api/v1/iac/scan`  
**Formats Supported:** Terraform (`.tf`, HCL, JSON), AWS CloudFormation (`.yaml`, `.yml`, JSON)  
**Version:** 2.0

---

## 1. Overview

CloudPathX V2.0 extends attack path prevention into the CI/CD deployment pipeline. By statically scanning Infrastructure as Code templates before they are applied, CloudPathX prevents the introduction of new identity attack paths, wildcards, and unconstrained trust delegations.

---

## 2. Rule Catalog

| Rule ID | Severity | Target Resource | Violation Condition | CI/CD Gate |
|---|---|---|---|---|
| **`CPX-IAC-001`** | `CRITICAL` | `aws_iam_policy`, `AWS::IAM::Policy` | Wildcard Action (`*`) in statement with `Effect: Allow` | **BLOCK** |
| **`CPX-IAC-002`** | `HIGH` | `aws_iam_role`, `AWS::IAM::Role` | Public Trust Principal (`*` or AWS root without conditions) | **BLOCK** |
| **`CPX-IAC-003`** | `HIGH` | IAM Policy / Statement | Dangerous Privilege Escalation action (`iam:PassRole`, `iam:PutUserPolicy`) | **BLOCK** |
| **`CPX-IAC-004`** | `MEDIUM` | `aws_s3_bucket_policy` | Publicly readable S3 bucket policy without VPC condition | **WARN** |

---

## 3. Pull Request (PR) Gate Logic

When an IaC scan runs:
- If **any** `CRITICAL` or `HIGH` violation is detected:
  - `gate_status`: **`BLOCK`**
  - CI/CD build fails, blocking PR merge.
- If only `MEDIUM` or `LOW` violations exist:
  - `gate_status`: **`WARN`**
- If 0 violations detected:
  - `gate_status`: **`PASS`**

---

## 4. Example Scan Request & Response

### Request
```json
{
  "content": "resource \"aws_iam_policy\" \"bad\" {\n  policy = jsonencode({\n    Statement = [{ Action = \"*\", Effect = \"Allow\", Resource = \"*\" }]\n  })\n}",
  "file_type": "terraform"
}
```

### Response
```json
{
  "file_type": "terraform",
  "gate_status": "BLOCK",
  "violations_count": 1,
  "violations": [
    {
      "rule_id": "CPX-IAC-001",
      "severity": "CRITICAL",
      "resource": "aws_iam_policy.bad",
      "description": "Wildcard Action (*) detected in IAM policy statement.",
      "recommendation": "Enumerate explicit service actions instead of wildcards."
    }
  ]
}
```
