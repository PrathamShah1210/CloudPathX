# Threat model

Assets: cloud policy inventories, event metadata, analyst notes, session tokens, local database and configured AWS access. Actors: administrator, analyst, viewer, unauthenticated network client, malicious imported JSON, compromised upstream dependency.

Trust boundaries: browser/API, API/PostgreSQL, worker/AWS SDK, imported JSON/analysis, operator/container host. The product does not execute attacker code or cloud attacks. AWS configuration values are names, region identifiers and role ARNs, not arbitrary URLs. Standard SDK endpoints are used, avoiding application-controlled URL fetching. Host administrator AWS SDK environment configuration remains trusted.

Controls: bearer authentication and backend role checks; salted password hashing; token hashing/expiry; SQLAlchemy parameterization; Pydantic validation; bounded JSON request size/event count; escaped React rendering; escaped PDF text; no automatic cloud remediation; separate private database network; loopback bind; audit records; timeouts and adaptive retry; CI dependency and secret checks. Cookie authentication is not used, so ambient-cookie CSRF is not the session mechanism.

Residual risks: login rate limiting is per process, not distributed; no MFA, SAML, password recovery, tenant segregation, at-rest field encryption or external audit sink. PostgreSQL administrators can change audit data. Large authorized inventories can consume CPU/memory. Some AWS error scopes contain resource names. Public deployment requires TLS, a hardened reverse proxy, centralized limits, backups, monitoring and an independent security review. A successful synthetic demonstration does not certify AWS authorization correctness.
