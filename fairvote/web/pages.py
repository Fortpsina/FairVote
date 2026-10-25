"""Static public pages: how it works, privacy, terms.

These pages are the honest part of the product: they state what the cryptography
does *not* protect (docs/01 §1.6). They are plain server-rendered HTML, readable
without JavaScript, and they are linked from every page's footer.
"""

from __future__ import annotations

from flask import Blueprint, Response, current_app, render_template

from .. import assets
from ..security.canonical import dumps

bp = Blueprint("pages", __name__)


@bp.get("/how-it-works")
def how_it_works():
    return render_template("pages/how.html")


@bp.get("/privacy")
def privacy():
    settings = current_app.extensions["fairvote.settings"]
    return render_template("pages/privacy.html", settings=settings)


@bp.get("/terms")
def terms():
    return render_template("pages/terms.html")


@bp.get("/manifest.json")
def asset_manifest():
    """The same document whose hash is committed at poll start."""
    response = Response(dumps(assets.manifest()).encode("utf-8"), mimetype="application/json")
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@bp.get("/verify")
def verify_ballot():
    """Instructions for the local lookup; the search itself happens in the browser."""
    return render_template("pages/verify.html")


@bp.get("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /auth/\nDisallow: /vote/\nDisallow: /account/\n"
    return Response(body, mimetype="text/plain")
