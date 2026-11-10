# AgentGuard

A deliberately vulnerable LLM agent, an attack suite, and switchable defences that measure how much each defence lowers the attack success rate.

**Status:** work in progress (Week 1 of 4).

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
