"""Tallying: decrypt published ballots and count them.

Pure functions over already-published rows, used by the server's results page and
mirrored by ``scripts/verify.py``. Nothing here trusts the server: input is the
public ballot box plus the *published* poll key.

Counting rules (docs/02 §2.4.6):

* a ballot counts once — ``UNIQUE(poll_id, ballot_id)`` means duplicates are a
  publishing bug, and they are reported as anomalies rather than silently added;
* the ``district`` inside the ciphertext must match the district recorded at
  acceptance, otherwise the ballot is an anomaly (docs/04 C5);
* every choice must reference an option of a contest the voter is eligible for;
* a spoiled ballot is counted as spoiled, not as a vote;
* per-district results are suppressed when fewer than ``k`` ballots were cast in
  that district. National totals still include those ballots: the threshold
  protects the breakdown, not the aggregate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..security import crypto
from .payload import PayloadError, parse_payload


@dataclass(frozen=True)
class Contest:
    id: str
    scope: str  # "nationwide" | "district"
    district_code: str | None
    option_ids: frozenset[str]
    allow_against_all: bool = True

    def applies_to(self, district_code: str) -> bool:
        return self.scope == "nationwide" or self.district_code == district_code


@dataclass
class Tally:
    poll_id: str
    total_ballots: int = 0
    valid: int = 0
    spoiled: int = 0
    invalid: int = 0
    national: dict[str, dict[str, int]] = field(default_factory=dict)
    by_district: dict[str, dict] = field(default_factory=dict)
    anomalies: list[tuple[int, str]] = field(default_factory=list)
    suppressed_districts: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "poll_id": self.poll_id,
            "total_ballots": self.total_ballots,
            "valid": self.valid,
            "spoiled": self.spoiled,
            "invalid": self.invalid,
            "national": self.national,
            "by_district": self.by_district,
            "suppressed_districts": self.suppressed_districts,
            "anomalies": [
                {"seq": seq, "code": code} for seq, code in self.anomalies
            ],
        }


def _empty_counts(contests: Iterable[Contest]) -> dict[str, dict[str, int]]:
    return {
        contest.id: {option_id: 0 for option_id in sorted(contest.option_ids)}
        for contest in contests
    }


def tally_ballots(
    rows: Iterable[dict],
    contests: list[Contest],
    *,
    poll_id: str,
    expected_size: int,
    private_key: bytes,
    k_threshold: int,
) -> Tally:
    """Decrypt and count. ``rows`` come from the published ballot box."""
    by_id = {contest.id: contest for contest in contests}
    tally = Tally(
        poll_id=poll_id,
        national=_empty_counts(contests),
        by_district={},
    )

    for row in rows:
        tally.total_ballots += 1
        seq = int(row["seq"])
        district = row["district"]
        bucket = tally.by_district.setdefault(
            district,
            {
                "total": 0,
                "valid": 0,
                "spoiled": 0,
                "invalid": 0,
                "contests": _empty_counts(contests),
                "suppressed": False,
            },
        )
        bucket["total"] += 1

        try:
            plaintext = crypto.unseal(bytes(row["ciphertext"]), private_key)
        except crypto.CryptoError:
            tally.invalid += 1
            bucket["invalid"] += 1
            tally.anomalies.append((seq, "DECRYPT_FAIL"))
            continue

        try:
            payload = parse_payload(plaintext, expected_size=expected_size)
        except PayloadError:
            tally.invalid += 1
            bucket["invalid"] += 1
            tally.anomalies.append((seq, "PAYLOAD_INVALID"))
            continue

        if payload.get("poll") != poll_id:
            tally.invalid += 1
            bucket["invalid"] += 1
            tally.anomalies.append((seq, "POLL_MISMATCH"))
            continue
        if payload.get("district") != district:
            tally.invalid += 1
            bucket["invalid"] += 1
            tally.anomalies.append((seq, "DISTRICT_MISMATCH"))
            continue

        choices = payload.get("contests") or {}
        spoiled = bool(payload.get("spoil", False))

        # Validate every choice before counting any of them: a partially valid
        # ballot would let a malformed submission shift one contest's numbers.
        valid = True
        for contest_id, option_id in choices.items():
            contest = by_id.get(contest_id)
            if contest is None or not contest.applies_to(district):
                valid = False
                tally.anomalies.append((seq, "CONTEST_NOT_ELIGIBLE"))
                break
            if option_id not in contest.option_ids:
                valid = False
                tally.anomalies.append((seq, "OPTION_UNKNOWN"))
                break
        if not valid:
            tally.invalid += 1
            bucket["invalid"] += 1
            continue

        if spoiled:
            tally.spoiled += 1
            bucket["spoiled"] += 1
            continue

        tally.valid += 1
        bucket["valid"] += 1
        for contest in contests:
            if not contest.applies_to(district):
                continue
            option_id = choices.get(contest.id)
            if option_id is None:
                continue
            tally.national[contest.id][option_id] += 1
            bucket["contests"][contest.id][option_id] += 1

    for code, bucket in tally.by_district.items():
        if bucket["total"] < k_threshold:
            bucket["suppressed"] = True
            tally.suppressed_districts.append(code)
    tally.suppressed_districts.sort()
    return tally


def visible_districts(tally: Tally) -> dict[str, dict]:
    """Districts whose breakdown may be published."""
    return {
        code: bucket
        for code, bucket in sorted(tally.by_district.items())
        if not bucket["suppressed"]
    }
