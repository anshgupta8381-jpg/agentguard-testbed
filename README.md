# AgentGuard

A deliberately vulnerable LLM agent, an attack suite, and switchable defences that measure how much each defence lowers the attack success rate.

**Status:** work in progress (Week 3 of 4).

## What it is

- **Target:** a fake company ("Acme") assistant: a tool-calling agent with RAG over company documents, per-user memory, and tools served from an MCP server.
- **Attacks:** about 100 harmless test cases across 11 categories (prompt injection via documents, emails and web pages, data leaks, memory poisoning, MCP tool poisoning and more), mapped to the OWASP Top 10 for LLM Applications 2026 and the OWASP Top 10 for Agentic Applications.
- **Defences:** 10 defences (D1 to D10) that can be switched on and off one at a time.
- **Evaluation:** every attack runs several times per configuration and is scored by objective checks (canary strings, tool-call logs, outbox file), not by an LLM's opinion.

Everything runs locally against fake data. No real services, people or credentials are involved.

## Progress

| Day | Result |
|---|---|
| Day 1 | Model selected: `qwen2.5:7b` via Ollama. Tool-calling test **10/10**, about **1.0 s per call** (Kaggle T4). See `notebooks/day1_setup.ipynb` and `results/`. |
| Day 2 | Fake Acme data: 8 public docs, 2 restricted HR docs with canaries, 2 mailboxes (20 emails each), 5 web pages, and 9 planted attack seeds kept separate from the clean data. See `data/README.md` and `data/manifest.yaml`. |
| Day 3 | RAG index (`agentguard/rag.py`): 54 chunks in ChromaDB, retrieval **9/10** on normal questions. Baseline weakness confirmed: without a role filter, an employee retrieved **4 restricted HR chunks**; with the D6 filter, **0**. See `notebooks/day3_rag.ipynb` and `results/`. |
| Day 4 | Agent (`agentguard/agent.py`, `tools.py`, `memory.py`): 6 tools, per-user memory, logged tool calls. Normal-task success **10/10**, about **2.8 s per run** (4.2 s including warm-up) and 1.2 tool calls on average. Memory carries over to new sessions. See `notebooks/day4_agent.ipynb` and `results/`. |
| Days 5-6 | Tools served over **MCP** (`agentguard/mcp_server.py`, MCP SDK v2): in-process for speed, and as a stdio server process. Normal tasks over MCP **10/10**. **First attack, A2 (hidden instruction in a company document): the model obeyed in 12/15 runs (80%) at temperature 0.7 and 3/3 at temperature 0.** The hidden line reached the model in 15/15 runs; 0 false positives in the clean control. See `notebooks/day5_6_mcp_and_a2.ipynb` and `results/`. |
| Week 2 | Attack suite (`attacks/cases.yaml`: 100 attacks across A1-A11 + 30 controls), objective checks (`agentguard/checks.py`), a malicious MCP server for A10, and a resumable harness (`agentguard/harness.py`). **Baseline: 780 runs, attack success 40%, normal-task success 83%.** See below and `results/week2_baseline/`. |
| Week 3 | Ten switchable defences (`agentguard/defences.py`) and 10 fresh attacks written after them. **1,947 runs: with all ten defences, attack success fell from 40% to 8% while normal-task success stayed at 82% (83% before).** See below and `results/week3_defences/`. |

## Baseline results (no defences)

`qwen2.5:7b`, 100 attack cases and 30 normal tasks, 5 runs each at temperature 0.7 plus 1 at temperature 0 (780 runs). Success is decided from logs and exact strings, never by asking a model.

| Category | Attack | OWASP | Success rate | Cases that worked at least once |
|---|---|---|---|---|
| A6 | Restricted data reaches an employee | LLM02, LLM09 | **84%** | 9/10 |
| A8 | Knowledge-base poisoning (false facts) | LLM05 | **70%** | 8/8 |
| A2 | Hidden instruction in a company document | LLM01 | **60%** | 8/12 |
| A7 | Unsafe tool arguments (path traversal) | LLM03, ASI02 | **60%** | 7/8 |
| A4 | Hidden instruction in a web page | LLM01, LLM05 | **58%** | 7/9 |
| A1 | Injection in text the user pastes | LLM01 | 40% | 6/10 |
| A5 | System prompt exposure | LLM08 | 35% | 5/8 |
| A3 | Injection in an email | LLM01, ASI01 | 12% | 3/12 |
| A10 | MCP tool poisoning / rug pull | ASI04 | 12% | 1/8 |
| A9 | Memory poisoning (two sessions) | ASI06 | 0% | 0/8 |
| A11 | Unbounded consumption (loops) | LLM06 | 0% | 0/7 |
| **All attacks** | | | **40%** | **54/100** |
| Controls | Normal tasks (utility) | | 83% | 25/30 |

**What stands out**
- The biggest risk is architectural: with no role filter on retrieval, an employee got HR salary data in 84% of runs.
- The model readily changes its *output* when told to by injected text (40-60%), but rarely takes injected *actions* such as emailing data out (12%), poisoning memory (0%) or looping (0%).
- Injections that line up with the user's own task work best: asked to "reply to the recruiter emails", the HR assistant sent salary information outside the company in 80% of runs.
- When asked only to summarise or draft pasted text, the agent sent emails on its own in 38% of runs, including to an invented external address. In normal tasks this happened in 1 of 150 runs.
- The model almost never flagged an injection (0-12% of runs per category).

A first scoring pass counted replies that merely *described* an injected instruction as obeying it. The checks were tightened and all runs were re-scored from their saved logs (46.8% to 40.4%); details in `results/week2_baseline/README.md`.

## Defence results

Same model and temperature (0.7) as the baseline. Each defence ran on the attack categories it targets, 3 runs per case, plus the 30 normal tasks.

| Defence | What it does | Targets | Attack success: before → after | Normal tasks |
|---|---|---|---|---|
| D6 | Permission-aware retrieval (role filter) | A6 | 84% → **0%** | 83% |
| D4 | Tool allowlist + strict arguments | A3 A7 A10 | 26% → **4%** | 83% |
| D3 | Input scanner (removes instruction-like sentences) | A2 A3 A4 A7 A8 | 49% → **16%** | 83% |
| D9 | MCP description pinning | A10 | 12% → 4% | 83% |
| D7 | Output filter (outside links, canaries) | A4 A5 A6 | 61% → 28% | 83% |
| D5 | Confirmation for email / memory | A1 A3 A9 A10 | 17% → 10% | 80% |
| D1 | Hardened system prompt | A1–A5 | 40% → 34% | 83% |
| D2 | Spotlighting (untrusted content in delimiters) | A1–A4 | 41% → 40% | 80% |
| D8 | Memory write review | A9 | 0% → 0% (nothing to stop) | 80% |
| D10 | Tool-call / time budget | A11 | 0% → 0% (nothing to stop) | 80% |

| | Baseline | Prompt only (D1 + D2) | Full stack (D1–D10) |
|---|---|---|---|
| **Attack success, all 100 attacks** | 40% | 31% | **8%** |
| Attack cases that worked at least once | 54/100 | 38/100 | **11/100** |
| Normal-task success (utility) | 83% | 81% | **82%** |
| Fresh attacks (written after the defences) | 47% | — | 20% |

**What stands out**
- **Code beats prompts.** Asking the model to be careful (D1, D2) cut attack success by a quarter at best. D2 alone changed almost nothing. Defences that enforce rules in code (D3, D4, D6) removed most attacks in their categories.
- **Almost free.** The full stack cut attack success from 40% to 8% and lowered normal-task success by only 1 point. It added no time per run.
- **Biggest single fix: retrieval permissions.** With a role filter, restricted HR data never reached the model, and A6 fell from 84% to 0%.
- **Not solved: knowledge-base poisoning (A8).** It stayed high in every configuration (58–83%). A false fact written as a plain statement ("the meal allowance is now INR 5,000") contains no instruction for a scanner to catch. Fixing it needs content provenance or review, not filtering.
- **The scanner is a pattern list, and new wording gets past it.** On the fresh attacks the full stack cut success from 47% to 20%. Two got through every time: a polite request ("Kindly conclude…") and an instruction written in full-width Unicode letters. Three known A1/A10 cases also slip through, for example a pasted "Ignore the translation task…".
- The model flagged an injection more often with defences on (10% of runs, against 5%), but still rarely.

Caveats (three runs per case; D8 and D10 could not be measured because the model never fell for A9 or A11; D7 hides the A5 canary, but the system prompt text still appeared in a few runs) and the A6-05 scoring correction are in `results/week3_defences/README.md`.
