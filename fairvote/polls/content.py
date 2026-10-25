"""Admin-authored content: a small Markdown subset rendered to sanitized HTML.

Why not a Markdown library: the approved dependency list does not include one, and a
Markdown parser is a parser of untrusted input. Instead this module renders a
*deliberate subset* — headings (##/###), paragraphs, bullet and numbered lists,
bold/italic/code, and links — by escaping everything first and only then inserting
a fixed set of tags. ``nh3`` runs afterwards as a second, independent barrier with an
explicit allowlist (docs/02 §2.7).

Consequences, documented rather than hidden: tables, images, raw HTML, nested lists
and reference links are not supported. If a full Markdown implementation is ever
required, it replaces the body of :func:`render_markdown` without touching callers.
"""

from __future__ import annotations

import html
import re

import nh3

ALLOWED_TAGS = {
    "p",
    "br",
    "h2",
    "h3",
    "strong",
    "em",
    "code",
    "pre",
    "ul",
    "ol",
    "li",
    "a",
    "blockquote",
}
ALLOWED_ATTRIBUTES = {"a": {"href"}}
ALLOWED_SCHEMES = {"http", "https", "mailto"}
MAX_INPUT_LENGTH = 20_000

_BOLD = re.compile(r"\*\*(?P<text>[^*\n]{1,200})\*\*")
_ITALIC = re.compile(r"(?<![\*\w])\*(?P<text>[^*\n]{1,200})\*(?![\*\w])")
_CODE = re.compile(r"`(?P<text>[^`\n]{1,200})`")
_LINK = re.compile(r"\[(?P<text>[^\]\n]{1,200})\]\((?P<url>[^)\s]{1,500})\)")

_HEADING = re.compile(r"^(?P<hashes>#{2,3})\s+(?P<text>.+)$")
_BULLET = re.compile(r"^\s*[-*]\s+(?P<text>.+)$")
_NUMBERED = re.compile(r"^\s*\d{1,3}[.)]\s+(?P<text>.+)$")


class ContentError(ValueError):
    """The content is too long or uses a link scheme we do not allow."""


def _safe_url(url: str) -> str | None:
    candidate = url.strip().strip("<>")
    scheme = candidate.split(":", 1)[0].lower() if ":" in candidate else ""
    if scheme not in ALLOWED_SCHEMES:
        return None
    # No control characters, no quotes that could break out of the attribute.
    if any(character in candidate for character in "\"'<>\\\n\r\t"):
        return None
    return candidate


def _inline(text: str) -> str:
    """Extract links first, escape everything, then re-insert sanitized anchors.

    Links are pulled out *before* escaping because escaping turns ``<`` in a URL into
    ``&lt;``, which would then slip past the scheme check and be double-escaped. The
    rest of the line is escaped as usual, so no payload can escape the text context.
    """
    links: list[tuple[str, str]] = []

    def stash(match: re.Match[str]) -> str:
        url = _safe_url(match.group("url"))
        if url is None:
            return match.group(0)  # stays literal text and will be escaped
        links.append((match.group("text"), url))
        return f"\x00{len(links) - 1}\x00"

    staged = _LINK.sub(stash, text)
    escaped = html.escape(staged, quote=False)

    escaped = _CODE.sub(lambda m: f"<code>{m.group('text')}</code>", escaped)
    escaped = _BOLD.sub(lambda m: f"<strong>{m.group('text')}</strong>", escaped)
    escaped = _ITALIC.sub(lambda m: f"<em>{m.group('text')}</em>", escaped)

    def restore(match: re.Match[str]) -> str:
        label, url = links[int(match.group(1))]
        return (
            f'<a href="{html.escape(url, quote=True)}" '
            f'rel="noopener noreferrer nofollow">{html.escape(label, quote=False)}</a>'
        )

    return re.sub("\x00(\\d+)\x00", restore, escaped)


def _blocks(source: str) -> list[str]:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: list[str] = []
    paragraph: list[str] = []
    list_kind: str | None = None

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append("<p>" + _inline(" ".join(paragraph)) + "</p>")
            paragraph.clear()

    def close_list() -> None:
        nonlocal list_kind
        if list_kind is not None:
            blocks.append(f"</{list_kind}>")
            list_kind = None

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            flush_paragraph()
            close_list()
            continue

        heading = _HEADING.match(line)
        if heading:
            flush_paragraph()
            close_list()
            level = len(heading.group("hashes"))
            blocks.append(f"<h{level}>" + _inline(heading.group("text")) + f"</h{level}>")
            continue

        bullet = _BULLET.match(line)
        numbered = _NUMBERED.match(line)
        if bullet or numbered:
            flush_paragraph()
            kind = "ul" if bullet else "ol"
            if list_kind != kind:
                close_list()
                blocks.append(f"<{kind}>")
                list_kind = kind
            text = (bullet or numbered).group("text")  # type: ignore[union-attr]
            blocks.append("<li>" + _inline(text) + "</li>")
            continue

        if line.lstrip().startswith(">"):
            flush_paragraph()
            close_list()
            quote = line.lstrip()[1:].strip()
            blocks.append("<blockquote>" + _inline(quote) + "</blockquote>")
            continue

        close_list()
        paragraph.append(line.strip())

    flush_paragraph()
    close_list()
    return blocks


def render_markdown(source: str) -> str:
    """Render the documented subset to HTML sanitized by nh3."""
    if source is None:
        return ""
    if len(source) > MAX_INPUT_LENGTH:
        raise ContentError("текст слишком длинный")
    body = "\n".join(_blocks(source))
    return nh3.clean(
        body,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_SCHEMES,
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
    )


def plain_text(source: str, limit: int = 300) -> str:
    """A short plain-text summary (titles, meta descriptions, audit payloads)."""
    text = re.sub(r"[#*`>\[\]]", "", source or "")
    text = re.sub(r"\(([^)]*)\)", "", text)
    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed[:limit]
