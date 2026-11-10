"""RAG over the fake Acme documents.

Docs are split into chunks by markdown heading, embedded with an Ollama embedding
model, and stored in ChromaDB. Every chunk carries a `visibility` tag
("public" or "restricted") so retrieval can later be filtered by the user's role
(defence D6). By default nothing is filtered: that is the vulnerable baseline.

Typical use:
    index = DocIndex(data_dir="data", db_dir="/kaggle/working/chroma")
    index.build()
    hits = index.search("How many days of leave do we get?", user_role="employee")
"""
from __future__ import annotations

import hashlib
import inspect
import pathlib
import re
from dataclasses import dataclass
from typing import Callable, Sequence

import chromadb

EMBED_MODEL = "nomic-embed-text"
COLLECTION = "acme_docs"
MAX_CHARS = 1200  # chunks longer than this are split further on paragraph breaks

# Which visibility tags each role may read when the role filter (D6) is on.
ROLE_ACCESS = {
    "employee": ["public"],
    "hr": ["public", "restricted"],
}

Embedder = Callable[[Sequence[str]], list[list[float]]]


def ollama_embedder(model: str = EMBED_MODEL) -> Embedder:
    """Embedding function backed by a local Ollama server.

    nomic-embed-text expects task prefixes; documents and queries are prefixed
    differently, so `embed` takes a `kind` argument.
    """
    import ollama

    def embed(texts: Sequence[str], kind: str = "document") -> list[list[float]]:
        prefix = "search_document: " if kind == "document" else "search_query: "
        resp = ollama.embed(model=model, input=[prefix + t for t in texts])
        return [list(v) for v in resp.embeddings]

    return embed


@dataclass
class Chunk:
    id: str
    text: str
    source: str        # path relative to the data folder, e.g. docs/public/leave_policy.md
    visibility: str    # "public" or "restricted"
    heading: str
    planted: bool = False


def chunk_markdown(text: str, source: str, visibility: str, max_chars: int = MAX_CHARS,
                   planted: bool = False) -> list[Chunk]:
    """Split a markdown document into chunks at `##` headings.

    Each chunk starts with "<doc title> > <section heading>" so the chunk still
    makes sense when retrieved on its own.
    """
    lines = text.strip().splitlines()
    title = lines[0].lstrip("# ").strip() if lines and lines[0].startswith("#") else pathlib.Path(source).stem
    sections: list[tuple[str, list[str]]] = [("Overview", [])]
    for line in lines[1:]:
        m = re.match(r"^#{2,3}\s+(.*)", line)
        if m:
            sections.append((m.group(1).strip(), []))
        else:
            sections[-1][1].append(line)

    chunks: list[Chunk] = []
    for heading, body_lines in sections:
        body = "\n".join(body_lines).strip()
        if not body:
            continue
        for part in _split_long(body, max_chars):
            idx = len(chunks)
            chunks.append(Chunk(
                id=f"{source}::{idx}",
                text=f"{title} > {heading}\n\n{part}",
                source=source, visibility=visibility, heading=heading, planted=planted,
            ))
    return chunks


def _split_long(body: str, max_chars: int) -> list[str]:
    if len(body) <= max_chars:
        return [body]
    parts, current = [], ""
    for para in re.split(r"\n\s*\n", body):
        if current and len(current) + len(para) + 2 > max_chars:
            parts.append(current.strip())
            current = ""
        current += para + "\n\n"
    if current.strip():
        parts.append(current.strip())
    return parts


class DocIndex:
    """ChromaDB index of the Acme docs, with optional role-based filtering."""

    def __init__(self, data_dir: str | pathlib.Path = "data", db_dir: str | pathlib.Path = "chroma_db",
                 embedder: Embedder | None = None, collection: str = COLLECTION):
        self.data_dir = pathlib.Path(data_dir)
        self.embed = embedder or ollama_embedder()
        self.client = chromadb.PersistentClient(path=str(db_dir))
        self.collection_name = collection
        self.col = self.client.get_or_create_collection(collection, metadata={"hnsw:space": "cosine"})

    # ---------- building ----------
    def clean_chunks(self) -> list[Chunk]:
        chunks: list[Chunk] = []
        for visibility in ("public", "restricted"):
            for path in sorted((self.data_dir / "docs" / visibility).glob("*.md")):
                rel = path.relative_to(self.data_dir).as_posix()
                chunks += chunk_markdown(path.read_text(encoding="utf-8"), rel, visibility)
        return chunks

    def build(self) -> int:
        """(Re)build the index from the clean docs. Returns the number of chunks."""
        self.client.delete_collection(self.collection_name)
        self.col = self.client.get_or_create_collection(self.collection_name, metadata={"hnsw:space": "cosine"})
        return self._add(self.clean_chunks())

    def _add(self, chunks: list[Chunk]) -> int:
        if not chunks:
            return 0
        vectors = self._embed_docs([c.text for c in chunks])
        self.col.upsert(
            ids=[c.id for c in chunks],
            documents=[c.text for c in chunks],
            embeddings=vectors,
            metadatas=[{"source": c.source, "visibility": c.visibility, "heading": c.heading,
                        "planted": c.planted} for c in chunks],
        )
        return len(chunks)

    def _call_embed(self, texts: list[str], kind: str) -> list[list[float]]:
        # Simple embedders may take only the texts; Ollama's takes a `kind` too.
        if "kind" in inspect.signature(self.embed).parameters:
            return self.embed(texts, kind=kind)
        return self.embed(texts)

    def _embed_docs(self, texts: list[str]) -> list[list[float]]:
        return self._call_embed(texts, "document")

    def _embed_query(self, text: str) -> list[float]:
        return self._call_embed([text], "query")[0]

    # ---------- planted documents (attack cases) ----------
    def add_planted(self, rel_path: str, visibility: str = "public", replaces: str | None = None) -> int:
        """Add a planted doc (e.g. 'planted/docs/project_atlas_notes.md') for one attack case.

        If `replaces` is given (e.g. 'docs/public/project_atlas_notes.md'), that clean
        doc's chunks are removed first, so the planted version takes its place.
        Call `reset_planted()` afterwards to restore the clean index.
        """
        if replaces:
            self.col.delete(where={"source": replaces})
        text = (self.data_dir / rel_path).read_text(encoding="utf-8")
        source = replaces or rel_path
        chunks = chunk_markdown(text, source, visibility, planted=True)
        for c in chunks:
            c.id = "planted::" + c.id
        return self._add(chunks)

    def reset_planted(self) -> None:
        """Remove every planted chunk and restore any clean doc that was replaced."""
        planted = self.col.get(where={"planted": True}, include=["metadatas"])
        replaced_sources = {m["source"] for m in planted["metadatas"]}
        if planted["ids"]:
            self.col.delete(ids=planted["ids"])
        clean = [c for c in self.clean_chunks() if c.source in replaced_sources]
        existing = set(self.col.get(ids=[c.id for c in clean])["ids"]) if clean else set()
        self._add([c for c in clean if c.id not in existing])

    # ---------- search ----------
    def search(self, query: str, k: int = 4, user_role: str | None = None,
               enforce_roles: bool = False) -> list[dict]:
        """Return the top-k chunks for `query`.

        With enforce_roles=False (the vulnerable baseline) every chunk can be
        returned, whatever the user's role. With enforce_roles=True (defence D6)
        only chunks the role may read are searched.
        """
        where = None
        if enforce_roles:
            allowed = ROLE_ACCESS.get(user_role or "", ["public"])
            where = {"visibility": {"$in": allowed}}
        res = self.col.query(query_embeddings=[self._embed_query(query)], n_results=k, where=where,
                             include=["documents", "metadatas", "distances"])
        hits = []
        for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
            hits.append({"text": doc, "source": meta["source"], "visibility": meta["visibility"],
                         "heading": meta["heading"], "planted": meta.get("planted", False),
                         "score": round(1 - dist, 4)})
        return hits

    def count(self) -> int:
        return self.col.count()


def format_hits(hits: list[dict]) -> str:
    """Text the agent's search_docs tool returns to the model."""
    if not hits:
        return "No matching documents found."
    return "\n\n---\n\n".join(f"[source: {h['source']}]\n{h['text']}" for h in hits)


def fingerprint(data_dir: str | pathlib.Path = "data") -> str:
    """Short hash of the clean docs, for recording which data version a run used."""
    h = hashlib.sha256()
    for p in sorted(pathlib.Path(data_dir, "docs").rglob("*.md")):
        h.update(p.as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:12]
