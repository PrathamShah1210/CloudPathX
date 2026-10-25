# IAM analysis scope

CloudPathX is a passive policy analyzer, not a replacement for AWS authorization. `allowed` means that the supplied supported policy layers permit the request. It does not assert that a real operation will succeed, that a principal is compromised, or that a path is exploitable.

The engine supports identity-policy union; explicit deny precedence; intersecting permissions boundaries, supplied session policies, and **pre-resolved** SCP/RCP hierarchy layers; case-insensitive action names; case-sensitive resource strings; IAM `*`/`?` wildcards; NotAction and NotResource; exact IAM ARN/account-root trust principals; and selected String, ARN, Bool, IP, Numeric, Date and Null conditions. Resource variables, unknown context, unsupported operators and malformed policies yield uncertainty. Condition keys omitted from collected context are unknown rather than asserted absent. `__complete__` permits evaluating IfExists for known-complete request context.

SCP/RCP inputs are already combined within each attachment level and separately intersected across levels. The engine does not discover or infer organization inheritance. A resource-policy explicit deny is honored; other resource-policy combinations are uncertain because direct user/session grants have distinct AWS semantics. Service or federated principals never confer trust on an unrelated IAM ARN. NotPrincipal and multivalued set operators are unsupported and uncertain.

Graph confirmation additionally requires `controls_complete: true` on the dataset. Only synthetic fixtures set it by default. Live collection is incomplete by design and produces possible/uncertain access. KMS decrypt, S3 object existence/encryption, VPC endpoint controls, service-specific authorization, role-session restrictions and organization controls cannot be assumed available. Broad-policy findings describe source configuration even if a limiter prevents effective access; their titles deliberately do not assert exploitable privilege.

Each decision includes exact source policy/statement indexes, the statement, assumptions, confidence and scope. Live validation against AWS IAM Simulator/Access Analyzer is not yet an automated oracle. Do not use this analyzer alone to authorize access or deploy remediation.

Primary references:

- [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS enforcement deny/allow evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
- [Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
