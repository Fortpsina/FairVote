"""Concurrent appends must never fork the chain."""

from __future__ import annotations

import threading

from fairvote.audit import chain

WORKERS = 4
PER_WORKER = 10


def test_concurrent_appends_serialise(stores) -> None:
    store = stores["audit_log"]
    errors: list[BaseException] = []
    start = threading.Barrier(WORKERS)

    def worker(index: int) -> None:
        try:
            start.wait(timeout=10)
            for n in range(PER_WORKER):
                chain.append(store, kind="admin.action", payload={"w": index, "n": n})
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(WORKERS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, errors
    rows = [entry.as_jsonl_row() for entry in chain.iter_entries(store)]
    assert len(rows) == WORKERS * PER_WORKER
    assert [row["seq"] for row in rows] == list(range(1, WORKERS * PER_WORKER + 1))
    assert chain.verify_rows(rows) == []
    seq, head_hash = chain.head(store)
    assert seq == WORKERS * PER_WORKER
    assert head_hash.hex() == rows[-1]["hash"]
