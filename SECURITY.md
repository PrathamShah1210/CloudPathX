# Security policy

This is a research and portfolio implementation with a documented IAM subset. Do not treat it as an exhaustive authorization oracle or deploy publicly without review. See THREAT_MODEL.md and IAM_ANALYSIS.md.

Do not include credentials, account secrets, sensitive policies or customer logs in public issues. Report a suspected vulnerability privately to the repository owner through an available private contact/GitHub advisory channel. No response SLA is promised.

The collector is read-only except temporary STS session issuance. Remediation is always simulated. Root credentials are rejected. Live credentials are obtained through the SDK provider chain and never stored in project data. Local `.env`, virtual environments, dependencies and logs are ignored by Git. The CI pipeline checks dependencies and secret patterns; these checks are defense in depth, not proof of security.
