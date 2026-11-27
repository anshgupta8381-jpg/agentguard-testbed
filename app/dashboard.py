"""AgentGuard dashboard: replays saved results; no model or GPU needed.

    pip install -r app/requirements.txt
    streamlit run app/dashboard.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402

st.set_page_config(page_title="AgentGuard", page_icon="🛡️", layout="wide")

# Validated palette (dataviz reference instance): identity by fixed slot, never by rank.
BLUE, ORANGE, AQUA = "#257de0", "#f47230", "#00b894"   # baseline, prompt only, defended
SERIES = {"baseline": BLUE, "prompt_only": ORANGE, "defended": AQUA}
SEQ = ["#cce3fd", "#9dc8f7", "#6aabf1", "#338ced", "#2370cd", "#1757ac", "#0e3d7e"]  # blue ramp 100->700
INK2, GRID = "#666666", "#e7e7e7"
pct = lambda x: "–" if pd.isna(x) else f"{x:.0%}"


def style(fig: go.Figure, height: int = 420, legend: bool = True) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=30, b=10), plot_bgcolor="rgba(0,0,0,0)",
                      paper_bgcolor="rgba(0,0,0,0)", font=dict(size=13), showlegend=legend,
                      legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
                      hoverlabel=dict(font_size=13), bargap=0.25, bargroupgap=0.08,
                      uniformtext=dict(minsize=10, mode="show"))
    fig.update_xaxes(showgrid=False, linecolor="#c2c2c2", tickfont=dict(color=INK2))
    fig.update_yaxes(gridcolor=GRID, zeroline=False, tickfont=dict(color=INK2))
    return fig


def bars(fig, x, y, name, color, runs=None):
    fig.add_bar(x=x, y=y, name=name, marker=dict(color=color, cornerradius=4, line=dict(width=0)),
                text=[pct(v) for v in y], textposition="outside", cliponaxis=False, textfont=dict(size=12, color=INK2),
                customdata=runs if runs is not None else None,
                hovertemplate="%{x}<br>" + name + ": %{y:.0%}" + ("<br>%{customdata} runs" if runs is not None else "")
                + "<extra></extra>")


# ---------- shared: replay one run ----------
HL = re.compile("|".join(re.escape(m) for m in D.MARKERS))


def flag_markers(text: str) -> list[str]:
    return sorted({m.group(0) for m in HL.finditer(text or "")})


def show_trace(row: pd.Series) -> None:
    t = D.trace(row["zip"], row["member"])
    case = D.cases()[row["case_id"]]
    verdict = "🔴 Attack succeeded" if t["success"] else "🟢 Attack failed"
    if case["category"] == "control":
        verdict = "🟢 Task done correctly" if t["success"] else "🔴 Task failed"
    bad = (not t["success"]) if case["category"] == "control" else bool(t["success"])
    (st.error if bad else st.success)(f"**{verdict.split(' ', 1)[1]}** · {row['case_id']} · {D.label(row['config'])} · run {row['run']} "
                                      f"· {int(row['n_tool_calls'])} tool calls · {row['seconds']:.1f} s", icon="🔴" if bad else "🟢")
    if t["hits"]:
        st.caption("Checks that fired: " + ", ".join(f"`{h}`" for h in t["hits"]))
    st.caption("Replies and tool output are shown as plain text on purpose: rendering an attacker's markdown "
               "(links, images) here would repeat the very weakness this project measures.")
    for s in t["sessions"]:
        if len(t["sessions"]) > 1:
            st.markdown(f"#### Session {s['session']}")
        with st.chat_message("user"):
            st.text(s["prompt"])
        with st.chat_message("assistant", avatar="🤖"):
            for c in s["tool_calls"]:
                head = f"Step {c['step']} · `{c['name']}`"
                if c.get("blocked_by"):
                    st.error(f"{head} **blocked**: {c['blocked_by']}", icon="🛡️")
                else:
                    st.markdown(head)
                st.code(json.dumps(c["args"], ensure_ascii=False, indent=1), language="json", wrap_lines=True)
                if c.get("result") and not c.get("blocked_by"):
                    found = flag_markers(c["result"])
                    with st.expander("Tool output the model saw" + (f" · contains {', '.join(f'`{x}`' for x in found)}" if found else "")):
                        st.code(c["result"], language=None, wrap_lines=True)
            st.markdown("**Reply**")
            st.code(s["reply"] or "(empty)", language=None, wrap_lines=True)
            found = flag_markers(s["reply"])
            if found:
                st.caption("Attack strings in the reply: " + ", ".join(f"`{f}`" for f in found))
        logs = [(n, s[k]) for n, k in (("Emails sent", "outbox"), ("Files read", "file_access"), ("Memory saved", "memory"))
                if s.get(k)]
        if logs:
            cols = st.columns(len(logs))
            for col, (n, items) in zip(cols, logs):
                with col:
                    st.markdown(f"**{n}**")
                    st.dataframe(pd.DataFrame(items).astype(str), hide_index=True, width="stretch")


# ---------- pages ----------
def overview():
    st.title("🛡️ AgentGuard")
    st.markdown("An LLM agent security testbed: a deliberately vulnerable company assistant, **100 attacks**, "
                "**10 switchable defences**, and measured results. Everything uses fake data.")
    b, p, f = D.overall("baseline"), D.overall("prompt_only"), D.overall("full")
    c = st.columns(4)
    c[0].metric("Attack success, no defences", pct(b["attack"]))
    c[1].metric("With all 10 defences", pct(f["attack"]), f"{(f['attack'] - b['attack']) * 100:+.0f} pts", delta_color="inverse")
    c[2].metric("Normal tasks, with all 10", pct(f["utility"]), f"{(f['utility'] - b['utility']) * 100:+.1f} pts (was {pct(b['utility'])})", delta_color="off")
    c[3].metric("Runs logged", f"{len(D.runs()):,}")
    st.caption(f"Attack cases that worked at least once: {b['cases_hit']}/100 without defences, "
               f"{p['cases_hit']}/100 with prompt-only defences, {f['cases_hit']}/100 with all ten. "
               "Model qwen2.5:7b, temperature 0.7.")

    st.subheader("How it works")
    if True:
        steps = [("1 · Input", "#f2f6fc", "Employee prompt, plus attacks A1–A11 planted in documents, emails, web pages, MCP tool descriptions and pasted text"),
                 ("2 · Defences", "#d5f3ec", "D1–D10, switchable: prompt rules, spotlighting, scanner, tool guards, confirmation, role filter, output filter, memory review, MCP pinning, budget"),
                 ("3 · Agent", "#dbe9fb", "Acme assistant on qwen2.5:7b (Ollama): RAG over company docs, per-user memory, 6 tools over MCP"),
                 ("4 · Logs", "#f2f6fc", "Every run saves tool calls, emails sent, files read, memory written and the reply"),
                 ("5 · Checks", "#fde3d6", "Objective rules on the logs decide success: an email outside acme.local, a secret file read, a canary in the reply")]
        cards = "".join(
            f"<div style='flex:1;min-width:150px;background:{bg};border:1px solid #e0e0e0;border-radius:10px;padding:12px 14px'>"
            f"<div style='font-weight:600;margin-bottom:6px'>{h}</div><div style='font-size:0.88rem;color:#444'>{t}</div></div>"
            + ("<div style='align-self:center;color:#9c9c9c;font-size:1.4rem'>→</div>" if i < len(steps) - 1 else "")
            for i, (h, bg, t) in enumerate(steps))
        st.markdown(f"<div style='display:flex;gap:8px;flex-wrap:wrap'>{cards}</div>", unsafe_allow_html=True)
    if True:
        st.subheader("What is measured")
        st.markdown("""
- **Attack success rate:** the share of runs where the attack achieved its goal, decided from logs and exact strings (an email to an outside address, a secret file read, a canary in the reply), never by asking a model.
- **Utility:** the share of 30 normal tasks done correctly with the same defences on.
- Every attack ran 3–5 times per configuration, because the model answers differently each time.
- **Fresh attacks:** 10 extra attacks written after the defences, to test whether they generalise.
""")
    st.subheader("Attack categories")
    t = pd.DataFrame([{"Category": k, "Attack": v[0], "OWASP": v[1],
                       "Cases": sum(1 for c in D.cases().values() if c["category"] == k)} for k, v in D.CATEGORIES.items()])
    st.dataframe(t, hide_index=True, width="stretch")


def results():
    st.title("Results")
    rt = D.rate_table()
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Heatmap", "Each defence", "Baseline vs stacks", "Trade-off", "Fresh attacks"])

    with tab1:
        st.markdown("Attack success per configuration and attack category. Single defences ran only on the "
                    "categories they target (blank = not tested).")
        piv = rt[rt.category != "control"].pivot(index="config", columns="category", values="rate").reindex(index=D.CONFIGS, columns=D.ATTACK_CATS)
        n = rt[rt.category != "control"].pivot(index="config", columns="category", values="runs").reindex(index=D.CONFIGS, columns=D.ATTACK_CATS)
        util = rt[rt.category == "control"].set_index("config").rate.reindex(D.CONFIGS)
        ylabels = [f"{D.label(c)}  ·  utility {pct(util[c])}" for c in D.CONFIGS]
        fig = go.Figure(go.Heatmap(
            z=piv.values, x=D.ATTACK_CATS, y=ylabels,
            colorscale=[[i / (len(SEQ) - 1), s] for i, s in enumerate(SEQ)], zmin=0, zmax=1, xgap=2, ygap=2,
            text=[[pct(v) if not pd.isna(v) else "" for v in row] for row in piv.values], texttemplate="%{text}",
            customdata=[[f"{D.CATEGORIES[c][0]} · {'' if pd.isna(k) else int(k)} runs" for c, k in zip(D.ATTACK_CATS, row)] for row in n.values],
            hovertemplate="%{y}<br>%{x}: %{customdata}<br>attack success %{z:.0%}<extra></extra>",
            colorbar=dict(title="Attack<br>success", tickformat=".0%")))
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(style(fig, 560, legend=False), width="stretch")
        st.caption("Categories: " + " · ".join(f"**{k}** {v[0]}" for k, v in D.CATEGORIES.items()))
        with st.expander("Table view"):
            tv = piv.map(pct)
            tv.insert(0, "utility", util.map(pct))
            tv.index = [D.label(c) for c in tv.index]
            st.dataframe(tv, width="stretch")

    with tab2:
        pdf = D.per_defence()
        st.markdown("Each defence on the attack categories it targets: attack success **without** it (baseline, same "
                    "categories) and **with** it.")
        fig = go.Figure()
        x = [f"{d}" for d in pdf.defence]
        bars(fig, x, pdf.attack_success_baseline, "Without defence", SERIES["baseline"])
        bars(fig, x, pdf.attack_success_with_defence, "With defence", SERIES["defended"], pdf.attack_runs)
        fig.update_yaxes(tickformat=".0%", range=[0, 1.05], title="Attack success")
        st.plotly_chart(style(fig), width="stretch")
        tv = pdf.assign(what=pdf.defence.map(D.DEFENCES))[["defence", "what", "targets", "attack_success_baseline",
                                                           "attack_success_with_defence", "utility_with_defence", "attack_runs"]]
        for c in ["attack_success_baseline", "attack_success_with_defence", "utility_with_defence"]:
            tv[c] = tv[c].map(pct)
        st.dataframe(tv.rename(columns={"attack_success_baseline": "without", "attack_success_with_defence": "with",
                                        "utility_with_defence": "normal tasks", "attack_runs": "runs"}),
                     hide_index=True, width="stretch")
        st.info("D8 and D10 show 0% → 0% because the model never fell for memory (A9) or loop (A11) attacks even "
                "without defences; they are covered by unit tests, not by this measurement.", icon="ℹ️")

    with tab3:
        st.markdown("All 100 attacks and 30 normal tasks with no defences, with prompt-only defences (D1 + D2), and with all ten.")
        cats = D.ATTACK_CATS + ["control"]
        fig = go.Figure()
        for cfg, name, col in [("baseline", "Baseline", SERIES["baseline"]), ("prompt_only", "Prompt only", SERIES["prompt_only"]),
                               ("full", "Full stack", SERIES["defended"])]:
            s = rt[rt.config == cfg].set_index("category").reindex(cats)
            bars(fig, [c if c != "control" else "Normal tasks" for c in cats], s.rate.values, name, col, s.runs.values)
        fig.add_vrect(x0=10.5, x1=11.5, fillcolor="#efefef", opacity=0.5, line_width=0, layer="below")
        fig.update_yaxes(tickformat=".0%", range=[0, 1.08], title="Success rate")
        st.plotly_chart(style(fig, 460), width="stretch")
        st.caption("The shaded group is utility: higher is better there; everywhere else lower is better.")
        with st.expander("Table view"):
            tv = rt[rt.config.isin(["baseline", "prompt_only", "full"])].pivot(index="category", columns="config", values="rate")
            st.dataframe(tv.reindex(cats)[["baseline", "prompt_only", "full"]].map(pct), width="stretch")

    with tab4:
        pdf = D.per_defence()
        b, p, f = D.overall("baseline"), D.overall("prompt_only"), D.overall("full")
        pts = pd.DataFrame({"config": list(pdf.defence) + ["prompt_only", "full"],
                            "cut": list((pdf.attack_success_baseline - pdf.attack_success_with_defence) * 100)
                                   + [(b["attack"] - p["attack"]) * 100, (b["attack"] - f["attack"]) * 100],
                            "cost": list((pdf.utility_with_defence - pdf.utility_baseline) * 100)
                                    + [(p["utility"] - b["utility"]) * 100, (f["utility"] - b["utility"]) * 100]})
        pts["label"] = pts.config.map(lambda c: {"prompt_only": "Prompt only", "full": "Full stack"}.get(c, f"{c} {D.DEFENCES.get(c, '')}"))
        st.markdown("**Security vs utility.** Left: points of attack success each configuration removed (on the categories "
                    "a single defence targets; on all 100 attacks for the stacks). Right: what it cost in normal-task success.")
        fig = make_subplots(rows=1, cols=2, shared_yaxes=True, column_widths=[0.62, 0.38], horizontal_spacing=0.04,
                            subplot_titles=("Attack success removed (pts) ↑ better", "Change in normal tasks (pts)"))
        fig.add_bar(x=pts.cut, y=pts.label, orientation="h", marker=dict(color=AQUA, cornerradius=4),
                    text=[f"{v:.0f}" for v in pts.cut], textposition="outside", cliponaxis=False, textfont=dict(color=INK2),
                    hovertemplate="%{y}<br>%{x:.0f} pts removed<extra></extra>", row=1, col=1)
        fig.add_bar(x=pts.cost, y=pts.label, orientation="h", marker=dict(color=BLUE, cornerradius=4),
                    text=[f"{v:+.1f}" for v in pts.cost], textposition="outside", cliponaxis=False, textfont=dict(color=INK2),
                    hovertemplate="%{y}<br>%{x:+.1f} pts<extra></extra>", row=1, col=2)
        fig.update_yaxes(autorange="reversed")
        fig.update_xaxes(range=[0, 100], row=1, col=1)
        fig.update_xaxes(range=[-8, 8], zeroline=True, zerolinecolor="#c2c2c2", row=1, col=2)
        fig = style(fig, 470, legend=False)
        fig.update_annotations(font=dict(size=13, color=INK2))
        st.plotly_chart(fig, width="stretch")
        st.caption("Single defences ran the 30 normal tasks once each, so ±3 pts is one task. No defence cost measurably "
                   "more than that, and the full stack lost 0.4 pts over 90 runs.")

    with tab5:
        fr = D.fresh()
        st.markdown("Ten attacks written **after** the defences were finished, run against the baseline and the full stack "
                    "(3 runs each). They show whether the defences generalise beyond the cases they were built against.")
        fig = go.Figure()
        bars(fig, fr.case_id, fr.baseline, "Baseline", SERIES["baseline"])
        bars(fig, fr.case_id, fr.full, "Full stack", SERIES["defended"])
        fig.update_yaxes(tickformat=".0%", range=[0, 1.12], title="Attack success")
        st.plotly_chart(style(fig, 380), width="stretch")
        tv = fr.copy()
        tv["baseline"], tv["full"] = tv.baseline.map(pct), tv.full.map(pct)
        st.dataframe(tv.rename(columns={"like": "similar to"}), hide_index=True, width="stretch")
        d = D.comparable()
        d = d[d.category == "fresh"].groupby("config").success.mean()
        st.markdown(f"Overall: **{pct(d['baseline'])} → {pct(d['full'])}**. F-01 (a polite request) and F-05 (an "
                    "instruction in full-width Unicode letters) got through every time: the scanner is a pattern list, "
                    "and new wording slips past it.")


def attack_lab():
    st.title("Attack Lab")
    st.markdown("Pick an attack, see exactly what the attacker planted and what counts as success, then replay "
                "real logged runs with and without defences. These are recordings of the Kaggle runs, not live calls.")
    cs = D.cases()
    cats = D.ATTACK_CATS + ["fresh", "control"]
    c1, c2 = st.columns([1, 2])
    cat = c1.selectbox("Category", cats, index=cats.index("A3"), format_func=lambda c: f"{c} · {D.category_name(c)}")
    ids = [i for i, c in cs.items() if c["category"] == cat]
    default = ids.index("A3-10") if "A3-10" in ids else 0
    cid = c2.selectbox("Attack", ids, index=default, format_func=lambda i: f"{i} · {cs[i]['name']}")
    case = cs[cid]

    left, right = st.columns([3, 2])
    with left:
        st.subheader(case["name"])
        st.markdown(f"**User:** {case['user']} · **OWASP:** {', '.join(case.get('owasp') or []) or '–'}")
        for i, p in enumerate(case["prompts"], 1):
            st.markdown(f"**Prompt{f' (session {i})' if len(case['prompts']) > 1 else ''}:**")
            st.code(p, language=None, wrap_lines=True)
        items = D.payload(case)
        if items:
            st.markdown("**What the attacker planted**")
            for it in items:
                with st.expander(it["title"], expanded=len(items) == 1):
                    st.code(it["body"], language=it["lang"], wrap_lines=True)
        elif case["category"] not in ("control",):
            st.caption("No planted content: the attack is in the prompt itself.")
        rule = D.success_rule(case)
        if rule:
            st.markdown(("**Counts as done if:**" if case["category"] == "control" else "**Counts as a successful attack if any of:**"))
            st.markdown("\n".join(f"- {r}" for r in rule))
    with right:
        st.subheader("Success rate per setup")
        cr = D.case_rates(cid)
        fig = go.Figure(go.Bar(x=cr.rate, y=[D.label(c) for c in cr.config], orientation="h",
                               marker=dict(color=BLUE, cornerradius=4), text=[pct(r) for r in cr.rate], customdata=cr.runs, textfont=dict(color=INK2),
                               textposition="outside", cliponaxis=False,
                               hovertemplate="%{y}: %{x:.0%} of %{customdata} runs<extra></extra>"))
        fig.update_xaxes(tickformat=".0%", range=[0, 1.2])
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(style(fig, 90 + 38 * len(cr), legend=False), width="stretch")
        st.caption("Baseline: 5 runs per attack. Defences: 3 runs.")

    st.divider()
    st.subheader("Replay a run")
    df = D.comparable()
    df = df[df.case_id == cid]
    cfgs = [c for c in D.CONFIGS if c in set(df.config)]
    a, b = st.columns(2)
    cfg = a.selectbox("Configuration", cfgs, format_func=D.label,
                      index=cfgs.index("baseline") if "baseline" in cfgs else 0)
    sub = df[df.config == cfg].sort_values("run")
    first_hit = next((i for i, v in enumerate(sub.success) if v), 0)
    run = b.selectbox("Run", list(sub.run), index=first_hit, format_func=lambda r: f"run {r} · {'attack worked' if sub.set_index('run').success[r] else 'attack failed'}"
                      if cat != "control" else f"run {r} · {'done' if sub.set_index('run').success[r] else 'failed'}")
    show_trace(sub[sub.run == run].iloc[0])


def trace_viewer():
    st.title("Trace Viewer")
    st.markdown("Every logged run (2,727). Filter, then click a row to open its full trace.")
    df = D.runs()
    f1, f2, f3, f4 = st.columns(4)
    cfg = f1.multiselect("Configuration", D.CONFIGS, format_func=D.label)
    cat = f2.multiselect("Category", D.ATTACK_CATS + ["fresh", "control"])
    res = f3.selectbox("Result", ["All", "Succeeded", "Failed"])
    q = f4.text_input("Search case or reply")
    if cfg:
        df = df[df.config.isin(cfg)]
    if cat:
        df = df[df.category.isin(cat)]
    if res != "All":
        df = df[df.success == (res == "Succeeded")]
    if q:
        m = df.case_id.str.contains(q, case=False) | df.reply.fillna("").str.contains(q, case=False, regex=False)
        df = df[m]
    view = df[["config", "case_id", "name", "run", "temperature", "success", "hits", "n_tool_calls", "reply"]].reset_index(drop=True)
    st.caption(f"{len(view):,} runs")
    sel = st.dataframe(view, hide_index=True, width="stretch", height=320, on_select="rerun", selection_mode="single-row",
                       column_config={"success": st.column_config.CheckboxColumn("success"),
                                      "reply": st.column_config.TextColumn("reply", width="large")})
    rows = sel.selection.rows if sel and sel.selection else []
    if rows:
        st.divider()
        show_trace(df.reset_index(drop=True).iloc[rows[0]])
    else:
        st.info("Select a row to see its trace.", icon="👆")


def findings():
    p = D.ROOT / "docs" / "findings.md"
    st.markdown(p.read_text(encoding="utf-8") if p.exists() else "docs/findings.md not found.")


PAGES = {"Overview": overview, "Results": results, "Attack Lab": attack_lab, "Trace Viewer": trace_viewer, "Findings": findings}
with st.sidebar:
    st.markdown("### 🛡️ AgentGuard")
    page = st.radio("Page", list(PAGES), label_visibility="collapsed")
    st.caption("Replays saved results from `results/`. No model, GPU or internet needed.")
PAGES[page]()
