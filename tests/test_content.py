"""Markdown subset: rendering, escaping and XSS resistance.

The security property under test is not "the payload string disappears" (it must stay
visible as text) but "the output contains only allowlisted tags, and no attributes
other than ``href`` on links".
"""

from __future__ import annotations

import re

import pytest

from fairvote.polls.content import (
    ALLOWED_TAGS,
    ContentError,
    MAX_INPUT_LENGTH,
    plain_text,
    render_markdown,
)

TAG_PATTERN = re.compile(r"<\s*/?\s*([a-zA-Z0-9]+)")
HANDLER_PATTERN = re.compile(r"<[^>]*\s(on[a-z]+)\s*=", re.IGNORECASE)


def tags(html: str) -> set[str]:
    return {match.lower() for match in TAG_PATTERN.findall(html)}


def assert_clean(html: str) -> None:
    assert tags(html) <= ALLOWED_TAGS, f"unexpected tags: {tags(html) - ALLOWED_TAGS}"
    assert not HANDLER_PATTERN.findall(html), "event handler attribute survived"


def test_paragraphs_and_headings() -> None:
    html = render_markdown("## Кандидаты\n\nПервый абзац.\n\n### О втором\n\nВторой абзац.")
    assert html.count("<h2>") == 1
    assert html.count("<h3>") == 1
    assert html.count("<p>") == 2


def test_lists() -> None:
    html = render_markdown("- один\n- два\n\n1. первый\n2. второй")
    assert html.count("<ul>") == 1
    assert html.count("<ol>") == 1
    assert html.count("<li>") == 4


def test_inline_formatting() -> None:
    html = render_markdown("**жирный** *курсив* `код`")
    assert "<strong>жирный</strong>" in html
    assert "<em>курсив</em>" in html
    assert "<code>код</code>" in html


def test_safe_links_survive() -> None:
    html = render_markdown("[сайт](https://example.org/page?x=1)")
    assert 'href="https://example.org/page?x=1"' in html
    assert 'rel="noopener noreferrer nofollow"' in html


def test_relative_and_scheme_less_links_are_rejected() -> None:
    for payload in ("[x](/admin)", "[x](//evil.example)", "[x](example.org)"):
        html = render_markdown(payload)
        assert "<a " not in html


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<iframe src=https://evil.example></iframe>",
        "<svg/onload=alert(1)>",
        '<a href="javascript:alert(1)">x</a>',
        "<style>body{display:none}</style>",
        "<form action=https://evil.example><input name=p></form>",
        "<object data=evil.swf></object>",
        "<base href=https://evil.example>",
        "<p onmouseover=alert(1)>текст</p>",
        '<a href="https://x" onclick="alert(1)">x</a>',
    ],
)
def test_raw_html_is_neutralised(payload: str) -> None:
    html = render_markdown(payload)
    assert_clean(html)
    assert "&lt;" in html  # the payload is visible as text, not executed


@pytest.mark.parametrize(
    "payload",
    [
        "[x](javascript:alert(1))",
        "[x](data:text/html;base64,PHNjcmlwdD4=)",
        "[x](vbscript:msgbox)",
        "[x](file:///etc/passwd)",
        '[x](https://example.org/"onmouseover="alert(1))',
        "[x](https://example.org/<script>)",
    ],
)
def test_dangerous_links_are_not_turned_into_anchors(payload: str) -> None:
    html = render_markdown(payload)
    assert "<a " not in html
    assert "href=" not in html
    assert_clean(html)


def test_escaped_text_cannot_break_out_of_attributes() -> None:
    html = render_markdown('Текст с кавычками " и угловыми < > скобками')
    assert_clean(html)
    assert "<" not in html.replace("<p>", "").replace("</p>", "")


def test_link_label_with_brackets_stays_text() -> None:
    html = render_markdown("[текст [вложенный]](https://example.org)")
    assert "<a " not in html


def test_blockquote() -> None:
    html = render_markdown("> цитата")
    assert "<blockquote>цитата</blockquote>" in html


def test_empty_input() -> None:
    assert render_markdown("") == ""
    assert render_markdown(None) == ""  # type: ignore[arg-type]


def test_too_long_input_is_refused() -> None:
    with pytest.raises(ContentError):
        render_markdown("а" * (MAX_INPUT_LENGTH + 1))


def test_render_is_stable() -> None:
    source = "## Заголовок\n\nТекст с [ссылкой](https://example.org) и **акцентом**."
    assert render_markdown(source) == render_markdown(source)


def test_plain_text_strips_markup() -> None:
    assert plain_text("## Заголовок\n\n**Жирный** [текст](https://example.org)") == (
        "Заголовок Жирный текст"
    )
    assert len(plain_text("а" * 1000)) == 300
