# API reference

The authoritative generated schema is `GET /openapi.json`; Swagger UI is `/docs`. Business routes use `/api/v1`. Login returns a one-hour token. Send `Authorization: Bearer <token>` for protected requests. Tokens are never query parameters.

| Area | Routes | Access |
|---|---|---|
| Session | POST /auth/login, GET /auth/me, POST /auth/logout | Login public, session routes authenticated |
| Inventory | GET /accounts, /identities, /policies, /resources | All authenticated roles |
| Analysis | GET /graph, /attack-paths, /analytics | All authenticated roles |
| Scan | POST /scans, GET /scans, GET /scans/{id}/stream | Analyst/admin mutation; authenticated reads |
| Policy | POST /policies/analyze | Analyst/admin |
| Events | GET /events, /alerts; POST /events/import | Authenticated reads, analyst/admin imports |
| Findings | GET /findings; PATCH /findings/{id} | Authenticated reads, analyst/admin updates |
| Incidents | GET/POST /incidents; PATCH /incidents/{id} | Authenticated reads, analyst/admin writes |
| Simulation | POST /remediation | Analyst/admin; never applies to AWS |
| Reports | GET /reports?format=json or pdf | Authenticated |
| Configuration | POST /accounts, GET/POST /users, PATCH /settings | Administrator |
| Audit | GET /audit | Administrator |
| Health | GET /health | Public minimal health |

List responses have `items` and `total` and accept bounded `limit`, `offset`, and where applicable `q`. Validation returns 422; denied roles return 403; missing or expired sessions return 401. Scan submissions queue background work; use scan history or an authenticated fetch stream to inspect completion/errors. Explicitly labeled partial results must not be interpreted as full visibility.
