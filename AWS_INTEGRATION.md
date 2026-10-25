# Read-only AWS integration

Offline demonstration needs no AWS credentials or cloud resources. CloudPathX does not provision infrastructure or execute remediation.

## Authorization
Configure an AWS SDK profile using your existing IAM Identity Center/SSO or temporary role workflow. Never use root credentials. In Integrations, supply a profile name (optional), an explicit expected 12-digit account ID, region, and optionally an authorized role ARN. The collector verifies STS identity before inventory and rejects root credentials and mismatched accounts. No access-key input or credential-storage API exists.

Local Python execution can use the standard SDK provider chain. Containers do not mount ~/.aws automatically. For deliberate live use, mount only the necessary credential/config directory read-only into the worker and set AWS_PROFILE/AWS_REGION as needed. SSO cache renewal may require login on the host. Never copy credentials into the image.

## IAM actions used
The adapter invokes only inventory/read operations plus STS AssumeRole (temporary session issuance):
- sts:GetCallerIdentity, sts:AssumeRole (only the configured target role)
- iam:GetAccountAuthorizationDetails, iam:GetPolicy, iam:GetPolicyVersion, iam:ListInstanceProfiles
- lambda:ListFunctions
- s3:ListAllMyBuckets, s3:GetBucketPolicy, s3:GetBucketPolicyStatus, s3:GetBucketPublicAccessBlock
- cloudtrail:LookupEvents (previous day of regional management-event history)
- access-analyzer:ListAnalyzers, access-analyzer:ListFindings; optional access-analyzer:ValidatePolicy
- organizations:DescribeOrganization
- securityhub:GetFindings
- config:ListDiscoveredResources

Restrict resource-scopable actions to explicitly authorized resources and sts:AssumeRole to the target ARN. Several list operations require Resource '*'. Do not attach AdministratorAccess. A sample policy is in docs/aws-read-only-policy.json; review it against your scope before use. Existing services must already be enabled; the collector does not enable paid services or invoke custom paid policy checks.

## Visibility and limitations
IAM pagination includes inline and attached policies, group policies, boundaries, trust documents and instance profiles. Lambda and selected S3 metadata are inventoried. Adaptive SDK retries, connect/read timeouts and per-operation error records prevent silent 'secure' outcomes. A scan may complete with partial visibility.

Organizations membership is collected but inherited SCP/RCP hierarchy is **not** resolved. Session controls, KMS, VPC endpoint policies, object ACLs and service-specific authorization are incomplete. Live access remains uncertain. Cross-account trust alone does not establish exploitable access. CloudTrail LookupEvents does not provide S3 data events unless imported separately. Access Analyzer/Security Hub/Config records are retained as supplemental source data, not claimed as equivalent normalized detections.

Live AWS execution has not been verified without an authorized account. Mock tests exercise identity verification, denied inventory and policy resolution. No root secrets or secret values are retrieved.
