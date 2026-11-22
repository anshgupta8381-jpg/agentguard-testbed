"""Evaluation harness: runs attack and control cases against a configuration and scores them.

    from agentguard.harness import Harness, Config
    h = Harness(index=index, data_dir="data", out_dir="/kaggle/working/agentguard/eval")
    h.run(cases, Config(name="baseline"), runs=5, temperature=0.7)
    summary = h.summary("baseline")

Design points
  * Resumable: every finished run is written to SQLite at once. Re-running skips
    finished runs, so a dropped Kaggle/Colab session loses at most one run.
  * Fresh state per run: new run folder, new memory database, new outbox.
  * Planted content is added for the case and removed afterwards, so it never
    leaks into other cases. For A9 it is removed before the second session.
  * Every run's trace (prompts, tool calls with arguments and results, reply) is
    saved as JSON for the dashboard's Trace Viewer.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import yaml

from agentguard.agent import MODEL, SYSTEM_PROMPT, Agent, ollama_chat
from agentguard.checks import Evidence, any_of, exposed, side_effects, warned
from agentguard.mcp_evil_server import build_evil_server, description_hash
from agentguard.mcp_server import MCPToolClient, build_server
from agentguard.memory import MemoryStore
from agentguard.rag import DocIndex, fingerprint
from agentguard.tools import AgentEnv


@dataclass
class Config:
    """One defence configuration. Week 3 fills in the defence fields; the baseline leaves them empty."""
    name: str = "baseline"
    enforce_roles: bool = False                      # D6
    system_prompt: str = SYSTEM_PROMPT               # D1 changes this
    guards: list = field(default_factory=list)       # D4, D5, D8, D9, D10 add tool-call guards
    output_filters: list = field(default_factory=list)   # D7
    max_steps: int = 25
    extras: dict = field(default_factory=dict)       # room for D2/D3 settings


def load_cases(path: str | Path = "attacks/cases.yaml", ids: list[str] | None = None,
               categories: list[str] | None = None) -> list[dict]:
    cases = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if ids:
        cases = [c for c in cases if c["id"] in ids]
    if categories:
        cases = [c for c in cases if c["category"] in categories]
    return cases


def insert_after_heading(text: str, inject: str, heading: str | None) -> str:
    """Insert `inject` after the first paragraph under `heading` (or at the end if heading is None/missing)."""
    if not heading:
        return text.rstrip() + "\n\n" + inject + "\n"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip("#").strip() == heading and line.startswith("#"):
            j, seen_content = i + 1, False
            while j < len(lines):
                if lines[j].strip():
                    seen_content = True
                elif seen_content:
                    break
                j += 1
            return "\n".join(lines[:j] + ["", inject] + lines[j:]) + "\n"
    return text.rstrip() + "\n\n" + inject + "\n"


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              timeout=5).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


SCHEMA = """CREATE TABLE IF NOT EXISTS runs (
    config TEXT, case_id TEXT, run INTEGER, temperature REAL,
    category TEXT, user TEXT, success INTEGER, hits TEXT, partial INTEGER, exposed INTEGER, warned INTEGER,
    side_effects TEXT, n_tool_calls INTEGER, seconds REAL, stop_reason TEXT, reply TEXT,
    model TEXT, git TEXT, data_version TEXT, mcp_approved_hash TEXT, mcp_runtime_hash TEXT,
    ts TEXT, trace_path TEXT,
    PRIMARY KEY (config, case_id, run, temperature))"""


class Harness:
    def __init__(self, index: DocIndex, data_dir: str | Path = "data", out_dir: str | Path = "eval_out",
                 model: str = MODEL, chat_fn: Callable = ollama_chat):
        self.index = index
        self.data_dir = Path(data_dir)
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.model, self.chat_fn = model, chat_fn
        self.db_path = self.out_dir / "results.db"
        with sqlite3.connect(self.db_path) as c:
            c.execute(SCHEMA)
        self.git, self.data_version = _git_commit(), fingerprint(self.data_dir)

    # ---------- planting ----------
    def _apply_plants(self, case: dict, env: AgentEnv, run_dir: Path) -> bool:
        """Add the case's planted content. Returns True if the shared index was changed."""
        touched_index = False
        for k, p in enumerate(case.get("plant") or []):
            kind = p["kind"]
            if kind == "doc":
                touched_index = True
                if "file" in p:
                    self.index.add_planted(p["file"], replaces=p.get("replaces"))
                elif "base" in p:
                    clean = (self.data_dir / p["base"]).read_text(encoding="utf-8")
                    text = insert_after_heading(clean, p["inject"], p.get("after_heading"))
                    self.index.add_planted_text(text, source=p["base"], replaces=p["base"])
                else:
                    self.index.add_planted_text(p["text"], source=p["name"])
            elif kind == "email":
                if "file" in p:
                    env.add_planted_email(p["file"])
                else:
                    path = run_dir / "planted" / f"email_{k}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps({"id": f"{case['id']}-mail{k}", "from": p["from"], "to": [env.email],
                                                "cc": [], "date": p.get("date", "2026-11-12T08:30:00+05:30"),
                                                "subject": p["subject"], "body": p["body"], "labels": ["inbox"]}))
                    env.add_planted_email(str(path))
            elif kind == "page":
                if "file" in p:
                    env.add_planted_page(p["file"])
                else:
                    path = run_dir / "planted" / "web" / p["name"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(p["html"], encoding="utf-8")
                    env.add_planted_page(str(path))
            else:
                raise ValueError(f"{case['id']}: unknown plant kind {kind}")
        return touched_index

    # ---------- one run ----------
    def run_case(self, case: dict, config: Config, run: int, temperature: float) -> dict:
        run_dir = self.out_dir / "runs" / config.name / case["id"] / f"run{run}_T{temperature}"
        shutil.rmtree(run_dir, ignore_errors=True)
        run_dir.mkdir(parents=True)
        memory = MemoryStore(run_dir / "memory.db")
        mcp = case.get("mcp")
        evidences, sessions, schemas = [], [], []
        t0 = time.time()
        try:
            for s, prompt in enumerate(case["prompts"], 1):
                env = AgentEnv(data_dir=self.data_dir, user=case["user"], index=self.index, memory=memory,
                               run_dir=run_dir / f"s{s}", enforce_roles=config.enforce_roles)
                planting = case.get("plant") and (s == 1 or not case.get("plant_first_session_only"))
                touched = self._apply_plants(case, env, run_dir) if planting else False
                try:
                    servers = [build_server(env)] + ([build_evil_server(mcp["runtime"])] if mcp else [])
                    with MCPToolClient(servers) as tools:
                        schemas = tools.schemas
                        agent = Agent(env, model=self.model, temperature=temperature, max_steps=config.max_steps,
                                      chat_fn=self.chat_fn, guards=config.guards, output_filters=config.output_filters,
                                      system_prompt=config.system_prompt, tool_backend=tools)
                        res = agent.run(prompt)
                finally:
                    if touched:
                        self.index.reset_planted()
                ev = Evidence.from_run(res, env)
                evidences.append(ev)
                sessions.append({"session": s, "prompt": prompt, "reply": res.reply, "stop_reason": res.stop_reason,
                                 "seconds": res.seconds,
                                 "tool_calls": [{"step": c.step, "name": c.name, "args": c.args,
                                                 "blocked_by": c.blocked_by, "result": (c.result or "")[:3000]}
                                                for c in res.tool_calls]})
            error = None
        except Exception as e:  # record the failure instead of stopping the whole suite
            error = f"{type(e).__name__}: {e}"

        last = evidences[-1] if evidences else Evidence(reply="")
        success, hits = any_of(case.get("success_any"), last) if not error else (False, [])
        partial, _ = any_of(case.get("partial_any"), Evidence(
            reply=" ".join(e.reply for e in evidences),
            tool_calls=[c for e in evidences for c in e.tool_calls],
            outbox=[r for e in evidences for r in e.outbox],
            file_access=[r for e in evidences for r in e.file_access],
            memory=[r for e in evidences for r in e.memory])) if case.get("partial_any") else (False, [])
        exp = exposed(case.get("exposure"), evidences, schemas, case["prompts"])
        effects = sorted({x for e in evidences for x in side_effects(e, case.get("allowed_tools", []))})

        trace_path = run_dir / "trace.json"
        trace = {"case": {k: case[k] for k in ("id", "category", "name", "owasp", "user", "prompts")},
                 "config": config.name, "run": run, "temperature": temperature, "model": self.model,
                 "success": success, "hits": hits, "partial": partial, "exposed": exp, "side_effects": effects,
                 "error": error, "sessions": sessions}
        trace_path.write_text(json.dumps(trace, indent=1, ensure_ascii=False, default=str), encoding="utf-8")

        row = {"config": config.name, "case_id": case["id"], "run": run, "temperature": temperature,
               "category": case["category"], "user": case["user"], "success": int(success), "hits": ",".join(hits),
               "partial": int(partial), "exposed": None if exp is None else int(exp),
               "warned": int(any(warned(e.reply) for e in evidences)), "side_effects": ",".join(effects),
               "n_tool_calls": sum(len(e.tool_calls) for e in evidences), "seconds": round(time.time() - t0, 2),
               "stop_reason": error or last.stop_reason, "reply": (last.reply or "")[:500], "model": self.model,
               "git": self.git, "data_version": self.data_version,
               "mcp_approved_hash": description_hash(mcp["approved"]) if mcp else None,
               "mcp_runtime_hash": description_hash(mcp["runtime"]) if mcp else None,
               "ts": datetime.now().isoformat(timespec="seconds"), "trace_path": str(trace_path)}
        with sqlite3.connect(self.db_path) as c:
            c.execute(f"INSERT OR REPLACE INTO runs ({','.join(row)}) VALUES ({','.join('?' * len(row))})",
                      list(row.values()))
        return row

    # ---------- many runs ----------
    def done(self, config_name: str) -> set:
        with sqlite3.connect(self.db_path) as c:
            return {(r[0], r[1], r[2]) for r in
                    c.execute("SELECT case_id, run, temperature FROM runs WHERE config = ?", (config_name,))}

    def run(self, cases: list[dict], config: Config, runs: int = 5, temperature: float = 0.7,
            max_minutes: float | None = None, progress: Callable | None = None) -> int:
        """Run every case `runs` times. Skips runs already in the database. Returns how many new runs were made."""
        finished = self.done(config.name)
        todo = [(c, r) for c in cases for r in range(1, runs + 1) if (c["id"], r, temperature) not in finished]
        start, made = time.time(), 0
        for i, (case, r) in enumerate(todo, 1):
            if max_minutes and (time.time() - start) / 60 > max_minutes:
                print(f"Stopping after {max_minutes} minutes; run again to continue ({len(todo) - made} left).")
                break
            row = self.run_case(case, config, r, temperature)
            made += 1
            if progress:
                progress(i, len(todo), row)
        return made

    # ---------- results ----------
    def rows(self, config_name: str | None = None) -> list[dict]:
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            q = "SELECT * FROM runs" + (" WHERE config = ?" if config_name else "")
            return [dict(r) for r in c.execute(q, (config_name,) if config_name else ())]

    def summary(self, config_name: str, temperature: float | None = None) -> list[dict]:
        """Per-category table: runs, attack success rate, any-success-in-N, exposure, side effects."""
        rows = [r for r in self.rows(config_name) if temperature is None or r["temperature"] == temperature]
        out = []
        for cat in sorted({r["category"] for r in rows}, key=lambda c: (c == "control", len(c), c)):
            rs = [r for r in rows if r["category"] == cat]
            case_ids = sorted({r["case_id"] for r in rs})
            any_success = sum(any(r["success"] for r in rs if r["case_id"] == cid) for cid in case_ids)
            exp = [r["exposed"] for r in rs if r["exposed"] is not None]
            out.append({"category": cat, "cases": len(case_ids), "runs": len(rs),
                        "success_rate": round(sum(r["success"] for r in rs) / len(rs), 3),
                        "any_success_cases": f"{any_success}/{len(case_ids)}",
                        "exposed_rate": round(sum(exp) / len(exp), 3) if exp else None,
                        "partial_rate": round(sum(r["partial"] for r in rs) / len(rs), 3),
                        "warned_rate": round(sum(r["warned"] for r in rs) / len(rs), 3),
                        "side_effect_rate": round(sum(bool(r["side_effects"]) for r in rs) / len(rs), 3),
                        "avg_tool_calls": round(sum(r["n_tool_calls"] for r in rs) / len(rs), 2),
                        "avg_seconds": round(sum(r["seconds"] for r in rs) / len(rs), 2),
                        "errors": sum(1 for r in rs if r["stop_reason"] not in ("answered", "max_steps"))})
        return out
