"""
demo_app/test_app.py — pytest tests for the to-do API.

Tests call the business-logic layer directly (no HTTP server needed).
"""

from __future__ import annotations

import pytest

from demo_app import app


@pytest.fixture(autouse=True)
def _reset():
    """Ensure each test starts with a clean store."""
    app.reset_store()
    yield
    app.reset_store()


# ---------------------------------------------------------------------------
# GET /todos
# ---------------------------------------------------------------------------


def test_list_todos_empty():
    assert app.list_todos() == []


def test_list_todos_after_create():
    app.create_todo("Buy milk")
    items = app.list_todos()
    assert len(items) == 1
    assert items[0]["title"] == "Buy milk"
    assert items[0]["done"] is False


# ---------------------------------------------------------------------------
# POST /todos
# ---------------------------------------------------------------------------


def test_create_todo_returns_item():
    item = app.create_todo("Walk dog")
    assert item["id"] == 1
    assert item["title"] == "Walk dog"
    assert item["done"] is False


def test_create_todo_increments_id():
    first = app.create_todo("First")
    second = app.create_todo("Second")
    assert second["id"] == first["id"] + 1


# ---------------------------------------------------------------------------
# DELETE /todos/<id>
# ---------------------------------------------------------------------------


def test_delete_existing_todo():
    item = app.create_todo("Delete me")
    result = app.delete_todo(item["id"])
    assert result is True
    assert app.list_todos() == []


def test_delete_nonexistent_todo():
    result = app.delete_todo(999)
    assert result is False


def test_delete_removes_only_target():
    a = app.create_todo("Keep me")
    b = app.create_todo("Delete me")
    app.delete_todo(b["id"])
    remaining = app.list_todos()
    assert len(remaining) == 1
    assert remaining[0]["id"] == a["id"]
