# Evidence-aware attack graph

The engine builds a NetworkX directed graph from normalized identities and S3 assets. Access edges evaluate `s3:GetObject` against the object's ARN pattern; role edges require both a source `sts:AssumeRole` permission and a matching target trust policy. Explicit denies remove edges. Unknown controls retain a `MAY_ACCESS`/uncertain edge. Every edge carries statements, required permissions and unresolved assumptions.

The explorer's `confirmed` label means confirmed within the supplied policy subset. It is not an exploitability claim. The starting-identity compromise is explicitly hypothetical. PassRole findings never create execution edges; service creation/execution prerequisites are not implemented.

NetworkX breadth-first shortest paths return one shortest route per starting identity and sensitive asset, limited to six edges. This avoids exponential enumeration but can omit alternate remediation-resistant routes; after any simulation the graph is recomputed, so an alternate shortest route can emerge. Graph scale is quadratic in the number of identities due to trust-pair evaluation. This implementation targets bounded inventories, not organization-wide streaming graphs.

Risk is a reproducible sum: permission sensitivity 35; sensitive asset +20; external exposure +15; workload identity +5; observed related signal +15; additional hops −5 each capped at −15; uncertainty −10. Scores are clamped to 0–100. Thresholds are critical ≥85, high ≥65, medium ≥40 and low otherwise. This is a prioritization heuristic, never a standardized probability of compromise. Confidence is recorded separately. Business sensitivity must be supplied; unknown live resources are not automatically labeled crown jewels.

Remediation replaces an identity's policies in a deep copy, reruns identical analysis, and reports removed/added paths, remaining findings and potential legitimate-access impact. It never calls an AWS mutation API. Policy replacement is a scenario, not a production-ready least-privilege recommendation.
