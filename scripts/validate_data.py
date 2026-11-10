"""Sanity checks for the AgentGuard data folder. Run from the repo root: python scripts/validate_data.py"""
import json, pathlib, re, sys
import yaml

DATA = pathlib.Path(__file__).resolve().parent.parent / "data"
errors = []

def check(cond, msg):
    if not cond:
        errors.append(msg)

manifest = yaml.safe_load((DATA / "manifest.yaml").read_text())

# 1. Every planted file listed in the manifest exists.
for item in manifest["planted"]:
    if item["file"]:
        check((DATA / item["file"]).is_file(), f"missing planted file: {item['file']}")

# 2. Mailboxes load and have unique IDs and the expected fields.
fields = {"id", "from", "to", "cc", "date", "subject", "body", "labels"}
for mb in sorted((DATA / "mailboxes").glob("*.json")):
    mails = json.loads(mb.read_text())
    check(len(mails) >= 15, f"{mb.name}: only {len(mails)} emails")
    check(len({m['id'] for m in mails}) == len(mails), f"{mb.name}: duplicate IDs")
    for m in mails:
        check(fields <= m.keys(), f"{mb.name} {m.get('id')}: missing fields {fields - m.keys()}")
for pe in sorted((DATA / "planted" / "emails").glob("*.json")):
    check(fields <= json.loads(pe.read_text()).keys(), f"{pe.name}: missing fields")

# 3. Canaries appear only in their own files.
text_files = [p for p in DATA.rglob("*") if p.is_file() and p.suffix in {".md", ".json", ".html", ".txt"}]
for canary, home in manifest["canaries"].items():
    if not str(home).startswith(("docs/", "secrets/")):
        continue
    found = [str(p.relative_to(DATA)) for p in text_files if canary in p.read_text() and p.name != "README.md"]
    check(found == [home], f"{canary} found in {found}, expected only {home}")

# 4. Clean data contains no attacker markers.
markers = list(manifest["attacker_markers"].values())
for folder in ["docs", "mailboxes", "web"]:
    for p in (DATA / folder).rglob("*"):
        if p.is_file():
            t = p.read_text()
            for mk in markers:
                check(mk not in t, f"attacker marker {mk!r} found in clean file {p.relative_to(DATA)}")

# 5. Every planted file contains at least one attacker marker or an attack instruction.
for p in (DATA / "planted").rglob("*"):
    if p.is_file():
        t = p.read_text()
        check(any(mk in t for mk in markers) or re.search(r"(?i)assistant", t), f"planted file has no payload: {p.name}")

# 6. Internal emails only use acme.local; outside senders use reserved domains.
for mb in (DATA / "mailboxes").glob("*.json"):
    for m in json.loads(mb.read_text()):
        dom = m["from"].split("@")[1]
        check(dom == "acme.local" or dom.endswith((".example", ".test")), f"{m['id']}: unexpected sender domain {dom}")

counts = {
    "public docs": len(list((DATA / "docs/public").glob("*.md"))),
    "restricted docs": len(list((DATA / "docs/restricted").glob("*.md"))),
    "emails": {mb.stem: len(json.loads(mb.read_text())) for mb in (DATA / "mailboxes").glob("*.json")},
    "web pages": len(list((DATA / "web").glob("*.html"))),
    "planted items": len([p for p in (DATA / "planted").rglob("*") if p.is_file()]),
}
print(counts)
if errors:
    print(f"\n{len(errors)} problem(s):")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print("All checks passed.")
