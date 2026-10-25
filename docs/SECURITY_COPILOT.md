# CloudPathX — Grounded Security Copilot Architecture

**Module:** `backend/app/copilot.py`  
**API Endpoint:** `POST /api/v1/copilot/query`  
**Version:** 2.0

---

## 1. Problem Statement & Design Objectives

Commercial AI security assistants frequently suffer from **hallucination**: fabricating permissions, assuming IAM conditions that do not exist, or hallucinating remediations that break production infrastructure.

The CloudPathX Security Copilot is designed with three strict engineering axioms:
1. **Evidence-Grounded**: Every statement must cite a verified IAM statement, active graph edge, or CloudTrail event.
2. **Provider-Agnostic**: Functions deterministically using local graph intelligence and can be backed by any LLM provider (Ollama, OpenAI, Anthropic, Gemini) through a uniform reasoning protocol.
3. **Audit Provenance**: Every response includes an explicit confidence score and a list of structured citations.

---

## 2. Evidence Retrieval & Reasoning Pipeline

```mermaid
flowchart LR
    UserQuery[Analyst Query\nNatural Language] --> IntentClassifier[Intent & Entity Classifier]
    IntentClassifier --> GraphExtractor[Graph Context Extractor]
    
    subgraph Evidence Graph
        Identities[Identity Catalog]
        Paths[Active Attack Paths]
        Rules[Detection Rule Matches]
        Findings[Prioritized Findings]
    end
    
    GraphExtractor <--> Evidence Graph
    GraphExtractor --> GroundingSynthesizer[Deterministic Grounding Synthesizer]
    GroundingSynthesizer --> CopilotResponse[Audited Response + Citations + Actions]
```

### 2.1 Supported Query Intents
- **Identity Privileges & Non-Human Identity Inspection**:
  *e.g., "Which non-human identities hold administrative access?"*
- **Attack Path Remediation & Choke Points**:
  *e.g., "What is the fastest way to break the critical path to the ProductionDB secret?"*
- **Path Differential Analysis**:
  *e.g., "Explain the difference between attack path 1 and path 2."*
- **Posture Summarization**:
  *e.g., "Provide an executive summary of our overall security posture."*

---

## 3. Grounded Response Format

```json
{
  "query": "Which non-human identities have admin privileges?",
  "answer": "Identified 1 over-privileged service principal: `role-build` (Build service role). It possesses unrestricted wildcard access (`*`) on all resources without condition boundaries.",
  "citations": [
    "IAM Deterministic Engine v2.0",
    "Entity: role-build",
    "Policy Statement: allow-all-actions",
    "Active Path: role-build -> sensitive-archive"
  ],
  "confidence": "High (98%)",
  "recommended_actions": [
    "Apply least-privilege scoping recommendation via Remediation Simulator",
    "Attach SCP boundary preventing sts:AssumeRole across external accounts"
  ]
}
```
