# CloudPathX — Attack Path Engine Specification

**Module:** `backend/app/engine.py`  
**Graph Framework:** NetworkX DiGraph & MultiDiGraph  
**Specification Version:** 2.0

---

## 1. Graph Model Definition

CloudPathX represents cloud permissions and identity topologies as a directed multigraph $G = (V, E)$.

### 1.1 Node Classes ($V$)
- `user`: Human IAM user principal.
- `role`: IAM assumed role.
- `service_role`: Non-human identity (e.g. AWS Lambda execution role, ECS task role).
- `instance_profile`: EC2 machine role container.
- `s3`: Amazon Simple Storage Service bucket / object prefix.
- `secretsmanager`: Secrets Manager secret (e.g., database credentials, API tokens).
- `rds`: Relational Database Service instance.
- `external_account`: Foreign AWS account ID in cross-account trust boundaries.

### 1.2 Edge Classes ($E$)
1. **`MAY_ACCESS`**: The principal holds verified Allow statements for specific data plane or management plane actions against the target resource.
2. **`CAN_ASSUME_ROLE`**: The principal satisfies the target role's `AssumeRolePolicyDocument` trust policy and possesses `sts:AssumeRole` permissions.
3. **`PASS_ROLE`**: The principal holds `iam:PassRole` privileges enabling them to attach an execution role to compute resources (EC2, Lambda).
4. **`CROSS_ACCOUNT_DELEGATION`**: Trust relationship spanning across AWS account boundaries.

---

## 2. Traversal Algorithms

### 2.1 All-Paths Discovery
The engine uses bounded Depth-First Search (DFS) with loop prevention to discover all distinct directed walks from untrusted entry nodes to designated Crown Jewel assets:

$$\mathcal{P} = \{ p \in \text{Paths}(G) \mid \text{source}(p) \in V_{\text{entry}} \land \text{target}(p) \in V_{\text{crown\_jewels}} \}$$

Cycle detection prevents infinite loops in circular role-assumption relationships.

### 2.2 Remediation Choke Point (Cut-Point) Detection
For each attack path $p = (v_1, v_2, \dots, v_k)$, intermediate vertices $\{v_2, \dots, v_{k-1}\}$ are evaluated across all active paths $\mathcal{P}$.

The **Choke Point** $c^*$ is defined as:

$$c^* = \arg\max_{v \in \bigcup p} |\{ p \in \mathcal{P} \mid v \in p \}|$$

Severing entitlements or trust permissions on $c^*$ eliminates the maximum number of converging attack vectors with minimal operational disruption.

### 2.3 Differential Path Comparison (`compare_attack_paths`)
When comparing two distinct attack vectors $P_A$ and $P_B$:
- **Shared Nodes:** $V_A \cap V_B$
- **Unique Nodes:** $V_A \setminus V_B$ and $V_B \setminus V_A$
- **Score Delta:** $\Delta S = \text{Score}(P_A) - \text{Score}(P_B)$
- **Common Cut-Point:** First shared choke point capable of mitigating both paths simultaneously.

---

## 3. Step-by-Step Narrative Generation

Every path is automatically translated into human-readable narrative steps:
1. Entry Principal (e.g., `Developer-Alice`)
2. Lateral Movement / Privilege Escalation Step (e.g., `assumes BuildServiceRole via sts:AssumeRole`)
3. Target Acquisition (e.g., `exfiltrates SecretsManager:ProductionDB via secretsmanager:GetSecretValue`)
