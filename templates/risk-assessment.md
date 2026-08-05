# AI Risk Assessment Template

> Copy this template for each AI system or agent deployment assessment.
> Aligns with NIST AI RMF (GOVERN, MAP, MEASURE, MANAGE).

## 1. System Description

| Field | Value |
|---|---|
| System name | [NAME] |
| Version | [VERSION] |
| Purpose | [What the system does] |
| Deployment date | [DATE] |
| Owner | [NAME/TEAM] |
| Risk tolerance | [Low/Medium/High] |

## 2. GOVERN: Risk Governance

- [ ] AI usage policy exists and is approved (HE-021)
- [ ] Roles and responsibilities are defined (AC-010)
- [ ] Accountability structures are documented (AC-015)
- [ ] Risk tolerance is documented and approved
- [ ] Monitoring and oversight processes are established (AC-013)

## 3. MAP: Risk Identification

### 3.1 LASM Threat Assessment

| Layer | Threat | Likelihood | Impact | Risk Level |
|---|---|---|---|---|
| L1 Foundation | | | | |
| L2 Cognitive | | | | |
| L3 Memory | | | | |
| L4 Tool Execution | | | | |
| L5 Integration | | | | |
| L6 Environment | | | | |
| L7 Governance | | | | |

### 3.2 CUSTODY Pillar Assessment

| Pillar | Control | Status | Gap |
|---|---|---|---|
| Conditions of Release | Authorization artifact (AC-001) | | |
| Conditions of Release | Task scope (AC-002) | | |
| Conditions of Release | Tool allowlist (AC-003) | | |
| Conditions of Release | Data inventory (AC-004) | | |
| Untrusted Input | Instruction hierarchy (AC-005) | | |
| Untrusted Input | Data separation (AC-006) | | |
| Untrusted Input | Model provenance (AC-007) | | |
| Untrusted Input | Memory validation (AC-008) | | |
| Supervision | Human approval (AC-009) | | |
| Supervision | Agent Rule of One (AC-010) | | |
| Supervision | Infrastructure enforcement (AC-011) | | |
| Supervision | Stop conditions (AC-012) | | |
| Traceability | Immutable logging (AC-013) | | |
| Traceability | Delegation tracing (AC-014) | | |
| Traceability | Separation of duties (AC-015) | | |
| Operational Controls | Secret broker (AC-016) | | |
| Operational Controls | Rate limits (AC-017) | | |
| Operational Controls | Non-root execution (AC-018) | | |
| Operational Controls | Default-deny egress (AC-019) | | |
| Operational Controls | Micro-segmentation (AC-020) | | |
| Dependency | Per-agent isolation (AC-021) | | |
| Dependency | Tool isolation (AC-022) | | |
| Yield | Immutable image (AC-023) | | |
| Yield | Ephemeral environment (AC-024) | | |
| Yield | Credential revocation (AC-025) | | |

## 4. MEASURE: Risk Assessment

### 4.1 Risk Scoring

| Risk ID | Threat | Likelihood (1-5) | Impact (1-5) | Risk Score | Mitigation | Residual Risk |
|---|---|---|---|---|---|---|
| R-001 | | | | | | |
| R-002 | | | | | | |

### 4.2 Harness Engineering Assessment

| Category | Weight | Score | Checklist Items Passing | Notes |
|---|---|---|---|---|
| Architectural Documentation | 20% | | | |
| Mechanical Constraints | 25% | | | |
| Testing & Stability | 25% | | | |
| Review & Drift Prevention | 15% | | | |
| AI-Specific Safeguards | 15% | | | |
| **Total** | **100%** | | | |

## 5. MANAGE: Risk Treatment

### 5.1 Critical Risks (Immediate Action Required)

| Risk ID | Treatment | Owner | Target Date | Status |
|---|---|---|---|---|
| | | | | |

### 5.2 High Risks (Action Within 30 Days)

| Risk ID | Treatment | Owner | Target Date | Status |
|---|---|---|---|---|
| | | | | |

### 5.3 Medium Risks (Action Within 90 Days)

| Risk ID | Treatment | Owner | Target Date | Status |
|---|---|---|---|---|
| | | | | |

### 5.4 Low Risks (Monitor)

| Risk ID | Treatment | Owner | Review Date | Status |
|---|---|---|---|---|
| | | | | |

## 6. Approval

| Role | Name | Date |
|---|---|---|
| System Owner | | |
| Security Lead | | |
| Risk Owner | | |

## 7. Review Schedule

- [ ] Quarterly review of risk register
- [ ] Annual comprehensive reassessment
- [ ] Ad hoc review after any AI security incident