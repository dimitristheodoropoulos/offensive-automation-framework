# Insurance Claims Triage Agent

A second, independent LangGraph pipeline built on the same architectural primitives as the OSAF pentest graph (`orchestration/graph.py`), applied to a different domain: automated fraud/risk triage for insurance claims. See the root [README.md](../README.md#beyond-security-applying-the-same-multi-agent-architecture-to-insurance-claims-triage) for the motivation behind this module.

## Architecture
intake_agent -> (valid) -> fraud_scoring_agent -> critic_agent
critic_agent -> (0 signals, <2 iters) -> retry fraud_scoring_agent
critic_agent -> (validated) -> llm_explainer_agent
llm_explainer_agent -> route_by_risk
route_by_risk -> (high) -> human_review -> report_node -> END
route_by_risk -> (low/medium) -> auto_approval -> report_node -> END

- **`intake_agent_node`** — validates that required claim fields are present (`claim_id`, `policy_id`, `claim_amount`, `claim_type`, `claim_date`, `policy_start_date`); ends the run early on missing data instead of scoring incomplete records.
- **`fraud_scoring_agent_node`** (`agents/insurance_claims_agent.py`) — invokes the `insurance_claim_fraud_scorer` adapter via the same `core/adapters.py` `ToolRegistry` used by the OSAF pentest graph.
- **`critic_agent_node`** — self-correction loop: if zero fraud signals were found and iteration count is below 2, forces a re-scoring pass rather than silently treating an empty result as "clean." Same pattern as OSAF's `critic_agent_node`.
- **`llm_explainer_agent_node`** — takes the deterministic fraud signals and risk score and asks the LLM (`gemini-2.5-flash`, same provider config as `orchestration/graph.py`) to produce a short, human-readable justification for the underwriter. The LLM only explains; it never sets or overrides the risk level — that stays fully deterministic and auditable. Untrusted signal data is passed through `orchestration/sanitizer.py`'s `sanitize_untrusted_input` before reaching the prompt, same as the CVE findings in `infra_agent_node`.
- **`human_review_node`** / **`auto_approval_node`** — routes on `risk_level`; high-risk claims are escalated for manual underwriter review rather than auto-decided.
- **`report_node`** — compiles a Markdown risk report per claim (risk score, LLM summary, itemized fraud signals).

State (`InsuranceState`, `orchestration/insurance_state.py`) is a single `TypedDict` — same design as `PentestState` — carrying the claim record, accumulated fraud signals, risk score/level, LLM summary, reasoning history, and loop-control fields.

## Honest note on fidelity

`insurance/claim_fraud_scorer.py` is **real, rule-based logic** — every signal (amount deviation from historical average, early-claim timing relative to policy start, missing required documentation by claim type, claim frequency) is computed directly from the input claim record, not hardcoded. It is not (yet) a trained ML classifier; a natural extension is replacing or supplementing it with a model trained on labeled fraud/non-fraud outcomes, following the same methodology as `models/classify_fuel_risk.py` in the [Enterprise Fleet Analytics](https://github.com/dimitristheodoropoulos/enterprise-fleet-analytics) project.

The `llm_explainer_agent_node`'s LLM call is real (`gemini-2.5-flash`) and degrades gracefully to a fallback string if the call fails — it never blocks or crashes the pipeline on an LLM outage, matching OSAF's approach to its own local-LLM fallback (`core/llm_provider.py`).

## Files

| File | Role |
|---|---|
| `orchestration/insurance_state.py` | `InsuranceState` TypedDict + `new_insurance_state()` initializer |
| `orchestration/insurance_graph.py` | Node definitions, conditional router, graph compilation |
| `agents/insurance_claims_agent.py` | Wraps the fraud-scoring adapter call for the `fraud_scoring_agent_node` |
| `adapters/insurance_claim_adapter.py` | `BaseToolAdapter` implementation wrapping `claim_fraud_scorer.py` in the shared `ToolExecutionResult`/`VulnerabilityRecord` contract |
| `insurance/claim_fraud_scorer.py` | Real rule-based fraud/risk signal computation |
| `main_insurance.py` | Standalone entrypoint — run with `python3 main_insurance.py` |
| `tests/test_claim_fraud_scorer.py`, `tests/test_insurance_claims_agent.py` | Test coverage for scoring logic and full graph behavior |

## Usage

```bash
python3 main_insurance.py
```

Run the test suite for this module specifically:
```bash
PYTHONPATH=. pytest tests/test_claim_fraud_scorer.py tests/test_insurance_claims_agent.py -v
```