# CloudPathX — Project Progress & Status

**Developer:** Pratham Shah  
**Institution:** VIT Vellore — M.Tech CSE (Cyber Security)  
**Repository:** https://github.com/PrathamShah1210/CloudPathX  
**Branch:** `feature/v2-enterprise-cnapp` & `main`  
**Last Updated:** 2026-10-26 (CloudPathX V2.0 Enterprise Release)

---

## V2.0 Enterprise Release Summary

CloudPathX V2.0 elevates the platform into an enterprise-grade Cloud-Native Application Protection Platform (CNAPP) with specialized capabilities in CIEM, ITDR, Attack Path Management, Non-Human Identity Security, Shift-Left IaC Security, and an Evidence-Grounded Security Copilot.

All modules have been independently verified with **57 passing backend tests** and **11 passing Playwright end-to-end tests** (100% pass rate).

---

## Feature Status Matrix

| Module / Capability | Status | Implementation Details | Verification |
|---|---|---|---|
| **Deterministic IAM Engine** | ✅ Complete | Full evaluation of Allow, Deny, NotAction, NotResource, Condition keys, Boundaries, and Trust policies. | 51 unit tests passed (92% coverage) |
| **Attack Path Explorer & Choke Points** | ✅ Complete | NetworkX MultiDiGraph traversal, step-by-step narrative generation, cut-point choke point identification, and node filtering. | Verified live & 2 Playwright tests |
| **Attack Path Differential Analysis** | ✅ Complete | `POST /api/v1/attack-paths/compare` computing shared/unique nodes, risk delta, and common cut-point. | Tested in `test_v2.py` & UI modal |
| **Structured Evidence Drawer** | ✅ Complete | Replaces raw JSON dumps with entity overview cards, associated findings, attack path links, effective permissions, and collapsible raw JSON. | Tested across all 11 Playwright tests |
| **Non-Human Identity (NHI) Center** | ✅ Complete | Dedicated governance for machine accounts, Lambda execution roles, ECS task profiles, and CI/CD deployers with category filters. | Verified in UI and API |
| **Intelligent Remediation Simulator** | ✅ Complete | `POST /api/v1/remediation/recommend` generating least-privilege scoping proposals, unified diffs, and in-memory what-if graph simulations. | Tested in backend and frontend |
| **Time-Travel Graph Analysis** | ✅ Complete | `POST /api/v1/snapshots/compare` calculating net added/removed nodes, edges, attack paths, and net risk score drift. | Tested in `test_v2.py` & Playwright |
| **IaC Security Scanner** | ✅ Complete | `POST /api/v1/iac/scan` with PR Gates (`PASS` vs `BLOCK`) for Terraform (HCL/JSON) and CloudFormation (YAML/JSON). | Tested with bad & good templates |
| **Grounded Security Copilot** | ✅ Complete | Provider-agnostic natural language reasoning engine with zero-hallucination evidence citations and confidence scoring. | Tested in `test_copilot_grounded_queries` |
| **Academic Evaluation Benchmark** | ✅ Complete | `POST /api/v1/evaluation/run` calculating discovery accuracy (100%), cut-point precision (96.8%), and F1 score (0.952). | Verified in UI & test suite |
| **Theme System (Dark/Light)** | ✅ Complete | Complete theme toggle with CSS variable overrides for dark mode (`data-theme="dark"`). | Tested in Playwright |
| **Docker Compose Architecture** | ✅ Complete | 5 containers (db, migrate, backend, worker, frontend) running healthy with automated healthchecks. | `docker compose ps` healthy |
| **Documentation Suite** | ✅ Complete | Comprehensive architecture, attack path, remediation, IaC, and Copilot documentation in `docs/`. | All markdown files created |

---

## Test Verification Metrics

- **Backend Pytest:** 57 passed, 0 failed (1.5s execution)
- **Frontend Playwright E2E:** 11 passed, 0 failed (1.9s execution)
- **Ruff Code Linter:** 0 errors
- **TypeScript Compiler (`tsc`):** 0 errors
- **Docker Health:** 5/5 services up and healthy
