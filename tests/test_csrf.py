"""CSRF tokens and the Origin / Sec-Fetch-Site guard."""

from __future__ import annotations

import pytest



def test_post_without_token_is_rejected(client, districts) -> None:
    response = client.post("/auth/login", data={"login": "x", "password": "y"})
    assert response.status_code == 400


def test_post_with_foreign_origin_is_rejected(client, districts, csrf) -> None:
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "x", "password": "y", "csrf_token": token},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


def test_post_with_cross_site_fetch_metadata_is_rejected(client, districts, csrf) -> None:
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "x", "password": "y", "csrf_token": token},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403


def test_post_with_same_origin_passes_the_guard(client, districts, csrf) -> None:
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "nobody", "password": "wrong-password-123", "csrf_token": token},
        headers={"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 401


def test_foreign_referer_is_rejected(client, districts, csrf) -> None:
    token = csrf(client, "/auth/login")
    response = client.post(
        "/auth/login",
        data={"login": "x", "password": "y", "csrf_token": token},
        headers={"Referer": "https://evil.example/page"},
    )
    assert response.status_code == 403


def test_get_requests_are_not_blocked(client, districts) -> None:
    assert client.get("/auth/login").status_code == 200
