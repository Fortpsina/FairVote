import re
import sqlite3
import sys
from pathlib import Path

doc = Path("docs/02-architecture.md").read_text(encoding="utf-8")
blocks = re.findall(r"```sql\n(.*?)```", doc, re.S)
print(f"sql blocks: {len(blocks)}")

con = sqlite3.connect(":memory:")
con.execute("PRAGMA foreign_keys=ON")
for i, block in enumerate(blocks, 1):
    try:
        con.executescript(block)
    except sqlite3.Error as exc:
        print(f"BLOCK {i} FAILED: {exc}")
        print(block[:600])
        sys.exit(1)

tables = [r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
print("tables:", len(tables), tables)

for gone in ("live_vote", "superseded_ballot", "proof_document"):
    assert gone not in tables, f"removed table still present: {gone}"

for t in ("ballot", "ballot_queue", "ballot_batch"):
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
    bad = [c for c in cols if c.lower() in ("user_id", "session_id", "ip", "user_agent")]
    print(f"{t}: {cols} bad={bad}")

con.execute("INSERT INTO poll(id,slug,title,summary,description_md,description_html,system,"
            "status,starts_at,ends_at,created_at,updated_at) VALUES "
            "('p1','s','t','s','md','<p>s</p>','list','scheduled','2026-01-01T00:00:00Z',"
            "'2026-02-01T00:00:00Z','x','x')")
con.execute("UPDATE poll SET status='open', public_key=x'aa', eligibility_root=x'bb' "
            "WHERE id='p1'")
try:
    con.execute("UPDATE poll SET title='hacked' WHERE id='p1'")
    print("FAIL: poll title updated after start")
    sys.exit(1)
except sqlite3.Error as exc:
    print("immutability ok:", exc)

con.execute("INSERT INTO entry(ts,kind,payload,prev_hash,hash) VALUES "
            "('x','poll.create','{}',x'00',x'01')")
try:
    con.execute("DELETE FROM entry")
    print("FAIL: audit entry deleted")
    sys.exit(1)
except sqlite3.Error as exc:
    print("append-only ok:", exc)

print("ALL DDL CHECKS PASSED")
