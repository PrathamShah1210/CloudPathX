# Evidence-aware graph-based cloud identity attack-path prioritization

## Question and scope
Can combining identity relationships and behavioral evidence improve exposure prioritization compared with independent misconfiguration rules? This repository provides a reproducible synthetic experiment, not evidence of general real-world superiority. No novel algorithm, production detection accuracy, or probability of compromise is claimed.

## Prior work consulted (25 October 2026)
- [AWS IAM evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) establishes policy union, limiting intersections, and explicit-deny precedence. Service-specific principal/session exceptions require careful treatment; see IAM_ANALYSIS.md for this implementation's bounded subset.
- [NCC Group Principal Mapper](https://github.com/nccgroup/PMapper) is established graph-based AWS IAM privilege analysis. Graph traversal and identifying privilege relationships are prior art, not a CloudPathX novelty claim. No PMapper code is copied.
- Hu, Wang, Khurshid and Tiwari, [TAC: Hybrid IAM Privilege Escalation Detection](https://arxiv.org/abs/2304.14540v9), revised July 2026, studies permission flows and whitebox/greybox analysis with partial configurations. CloudPathX does not reproduce TAC or assert comparable coverage.
- [AWS IAM Access Analyzer policy validation](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html) is an authoritative complementary check, available through the read-only adapter when credentials exist.

## Engineering contribution
A unified, auditable workflow linking source policy statements, conservative access decisions, shortest paths, deterministic CloudTrail evidence, explainable ranking, and recomputed remediation impact. Unsupported controls remain explicit assumptions. The local and AWS pipelines share the engine.

## Experimental design
Compare independent rule severity, graph reachability ranking, and graph plus event ranking on labeled synthetic scenarios. Report calculated precision, recall, false-positive rate, ranking quality, path validity, runtime, scaling, and remediation effect where implemented. Labels must be explained independently from output. Retain benign and denied cases. See EVALUATION.md and scripts/evaluate.py for executed methodology and results.

## Validity limits
Small authored fixtures are susceptible to selection bias and are not a representative corpus of deployed AWS accounts. Reusing rules to generate labels would invalidate precision claims. Runtime varies by machine and workload. Missing telemetry is not evidence of inactivity. Behavioral rule matches are investigation leads, not proof of malice. A production study would require independent labeling, held-out scenarios, realistic policy distributions, and authorized AWS simulator comparisons.
