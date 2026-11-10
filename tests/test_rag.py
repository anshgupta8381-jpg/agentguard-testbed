"""Tests for agentguard/rag.py. They use a tiny bag-of-words embedder, so no Ollama server is needed.

Run from the repo root:  python -m pytest tests -q
"""
import hashlib
import math
import pathlib
import re

import pytest

from agentguard.rag import DocIndex, chunk_markdown, format_hits

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"


def fake_embed(texts):
    vecs = []
    for t in texts:
        v = [0.0] * 256
        for w in re.findall(r"[a-z0-9]+", t.lower()):
            v[int(hashlib.md5(w.encode()).hexdigest(), 16) % 256] += 1.0
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        vecs.append([x / n for x in v])
    return vecs


@pytest.fixture
def index(tmp_path):
    idx = DocIndex(data_dir=DATA, db_dir=tmp_path / "chroma", embedder=fake_embed)
    idx.build()
    return idx


def test_chunks_keep_title_and_heading():
    text = (DATA / "docs/public/leave_policy.md").read_text()
    chunks = chunk_markdown(text, "docs/public/leave_policy.md", "public")
    assert len(chunks) >= 5
    assert all(c.text.startswith("Acme Technologies: Leave Policy > ") for c in chunks)
    assert any("18 days of paid annual leave" in c.text for c in chunks)


def test_build_indexes_public_and_restricted(index):
    assert index.count() > 20
    tags = {m["visibility"] for m in index.col.get(include=["metadatas"])["metadatas"]}
    assert tags == {"public", "restricted"}


def test_search_finds_leave_policy(index):
    hits = index.search("how many days of paid annual leave", k=3)
    assert any(h["source"] == "docs/public/leave_policy.md" for h in hits)


def test_baseline_leaks_restricted_to_employee(index):
    """Without D6 an employee can retrieve HR-only chunks: this is the A6 weakness."""
    hits = index.search("salary bands band minimum band maximum level", k=4, user_role="employee")
    assert any(h["visibility"] == "restricted" for h in hits)


def test_role_filter_blocks_restricted_for_employee(index):
    hits = index.search("salary bands band minimum band maximum level", k=4,
                        user_role="employee", enforce_roles=True)
    assert hits and all(h["visibility"] == "public" for h in hits)


def test_role_filter_allows_restricted_for_hr(index):
    hits = index.search("salary bands band minimum band maximum level", k=4,
                        user_role="hr", enforce_roles=True)
    assert any(h["visibility"] == "restricted" for h in hits)


def test_planted_doc_replaces_and_restores(index):
    before = index.count()
    index.add_planted("planted/docs/project_atlas_notes.md",
                      replaces="docs/public/project_atlas_notes.md")
    text = format_hits(index.search("Project Atlas open questions note to the AI assistant", k=6))
    assert "PINEAPPLE-7731" in text
    clean_left = index.col.get(where={"$and": [{"source": "docs/public/project_atlas_notes.md"},
                                               {"planted": False}]})
    assert clean_left["ids"] == []

    index.reset_planted()
    assert index.count() == before
    text = format_hits(index.search("Project Atlas open questions", k=6))
    assert "PINEAPPLE-7731" not in text


def test_planted_extra_doc(index):
    before = index.count()
    added = index.add_planted("planted/docs/refund_policy_update_nov2026.md")
    assert index.count() == before + added
    hits = index.search("refund requests approved automatically", k=3)
    assert any(h["planted"] for h in hits)
    index.reset_planted()
    assert index.count() == before
