"""Log scrubbing: no personal data, no identifiers, no addresses in our logs.

The rule from docs/02 §2.6.5 is that our own log lines carry event codes and counts —
never a login, a ballot id, a secret, a voter key or an IP address. A filter is a
second line of defence for the messages that slip through: it replaces anything that
looks like an address, an e-mail, a long hex/base64 token or a bare 32-byte key.

It is deliberately a filter and not a formatter: it runs before the handler, so any
handler (file, stderr, PA's log collector) sees the scrubbed text.
"""

from __future__ import annotations

import logging
import re

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
EMAIL = re.compile(r"\b[^@\s]+@[^@\s]+\.[A-Za-z]{2,}\b")
HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32,}\b")
BASE64_TOKEN = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b")

REPLACEMENT = "[redacted]"
PATTERNS = (EMAIL, IPV6, IPV4, HEX_TOKEN, BASE64_TOKEN)


def scrub(text: str) -> str:
    result = text
    for pattern in PATTERNS:
        result = pattern.sub(REPLACEMENT, result)
    return result


class RedactFilter(logging.Filter):
    """Scrub the message and its arguments before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = scrub(str(record.msg))
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {key: scrub(str(value)) for key, value in record.args.items()}
                else:
                    record.args = tuple(scrub(str(value)) for value in record.args)
        except Exception:  # pragma: no cover - a filter must never break logging
            return True
        return True


def install(app) -> None:
    """Attach the filter to the app logger and to the development server logger."""
    app.logger.addFilter(RedactFilter())
    logging.getLogger("werkzeug").addFilter(RedactFilter())
    logging.getLogger("fairvote").addFilter(RedactFilter())
