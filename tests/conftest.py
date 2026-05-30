import sqlite3

import pytest

from keychain.audit_emitter import AuthEvent, AuthEventLog
from keychain.proxy import AuthHelper
from keychain.rate_limiter import RateLimiter
from keychain.request_handler import RequestHandler
from keychain.token_store import TokenStore


@pytest.fixture
def auth_log():
    return AuthEventLog()


@pytest.fixture
def benign_event():
    return AuthEvent(
        actor="user-001",
        method="bearer",
        outcome="ok",
        request_path="/v1/chat/completions",
        key_prefix="sk-abc12345",
        detail="route=primary",
    )


@pytest.fixture
def populated_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE verification_tokens (token TEXT PRIMARY KEY, key_id TEXT, scope TEXT)")
    db.execute("INSERT INTO verification_tokens VALUES (?, ?, ?)", ("tok-valid-001", "k-001", "chat:read"))
    db.execute("INSERT INTO verification_tokens VALUES (?, ?, ?)", ("tok-valid-002", "k-002", "chat:write"))
    db.execute("INSERT INTO verification_tokens VALUES (?, ?, ?)", ("tok-admin-001", "k-admin", "admin"))
    return db


@pytest.fixture
def request_handler(populated_db):
    return RequestHandler(populated_db)


@pytest.fixture
def token_store():
    store = TokenStore()
    store.register("bearer", "tok-valid-001", actor="user-001", scope="chat:read")
    store.register("bearer", "tok-valid-002", actor="user-002", scope="chat:write")
    return store


@pytest.fixture
def auth_helper(token_store):
    return AuthHelper(token_store)


@pytest.fixture
def rate_limiter():
    return RateLimiter(window_seconds=60.0)
