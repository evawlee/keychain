import sqlite3

import pytest

from keychain.audit_emitter import AuthEvent, AuthEventLog
from keychain.proxy import AuthError, AuthHelper, Principal
from keychain.rate_limiter import RateLimiter
from keychain.request_handler import RequestHandler, VerifiedKey
from keychain.token_store import TokenRecord, TokenStore


class TestAuthEventLogHappyPath:

    def test_record_appends_entry(self, auth_log, benign_event):
        auth_log.record_auth_event(benign_event)
        assert len(auth_log) == 1

    def test_record_preserves_actor_in_entry(self, auth_log, benign_event):
        auth_log.record_auth_event(benign_event)
        line = auth_log.entries()[0]
        assert "user-001" in line

    def test_record_preserves_method_label(self, auth_log, benign_event):
        auth_log.record_auth_event(benign_event)
        line = auth_log.entries()[0]
        assert "bearer" in line

    def test_record_preserves_request_path(self, auth_log, benign_event):
        auth_log.record_auth_event(benign_event)
        line = auth_log.entries()[0]
        assert "/v1/chat/completions" in line

    def test_record_multiple_events_accumulates(self, auth_log, benign_event):
        for _ in range(4):
            auth_log.record_auth_event(benign_event)
        assert len(auth_log.entries()) == 4

    def test_clear_resets_log(self, auth_log, benign_event):
        auth_log.record_auth_event(benign_event)
        auth_log.clear()
        assert auth_log.entries() == []


class TestRequestHandlerHappyPath:

    def test_verify_bearer_returns_known_key(self, request_handler):
        result = request_handler._verify_bearer("tok-valid-001")
        assert result is not None
        assert result.key_id == "k-001"

    def test_verify_bearer_returns_scope(self, request_handler):
        result = request_handler._verify_bearer("tok-valid-001")
        assert result.scope == "chat:read"

    def test_verify_bearer_returns_none_for_unknown_token(self, request_handler):
        result = request_handler._verify_bearer("tok-not-registered")
        assert result is None

    def test_lookup_scope_returns_scope_for_admin(self, request_handler):
        scope = request_handler.lookup_scope("tok-admin-001")
        assert scope == "admin"

    def test_lookup_scope_none_for_unknown(self, request_handler):
        scope = request_handler.lookup_scope("tok-not-registered")
        assert scope is None


class TestRateLimiterHappyPath:

    def test_touch_records_key(self, rate_limiter):
        rate_limiter.touch("k-touch-records", 100.0)
        assert "k-touch-records" in rate_limiter.get_active_keys()

    def test_touch_records_latest_timestamp(self, rate_limiter):
        rate_limiter.touch("k-touch-latest", 100.0)
        rate_limiter.touch("k-touch-latest", 250.0)
        assert rate_limiter.get_active_keys()["k-touch-latest"] == 250.0

    def test_record_request_accumulates(self, rate_limiter):
        for t in (100.0, 110.0, 120.0):
            rate_limiter.record_request("k-accumulates", t)
        assert len(rate_limiter.get_rate_state()["k-accumulates"]) == 3

    def test_count_recent_inside_window(self, rate_limiter):
        for t in (100.0, 110.0, 120.0):
            rate_limiter.record_request("k-inside-window", t)
        assert rate_limiter.count_recent("k-inside-window", 130.0) == 3

    def test_count_recent_outside_window(self, rate_limiter):
        rate_limiter.record_request("k-outside-window", 10.0)
        assert rate_limiter.count_recent("k-outside-window", 1000.0) == 0


class TestAuthHelperHappyPath:

    def test_resolve_principal_for_bearer(self, auth_helper):
        principal = auth_helper.resolve_principal("bearer", "tok-valid-001")
        assert principal is not None
        assert principal.actor == "user-001"

    def test_resolve_principal_returns_scope(self, auth_helper):
        principal = auth_helper.resolve_principal("bearer", "tok-valid-002")
        assert principal.scope == "chat:write"

    def test_resolve_principal_unknown_credential_returns_none(self, auth_helper):
        result = auth_helper.resolve_principal("bearer", "tok-unregistered")
        assert result is None


class TestTokenStoreHappyPath:

    def test_register_and_lookup(self):
        store = TokenStore()
        store.register("bearer", "tok-x", actor="alice", scope="chat:read")
        assert store.lookup("bearer", "tok-x") == TokenRecord(actor="alice", scope="chat:read")

    def test_lookup_unknown_returns_none(self):
        store = TokenStore()
        assert store.lookup("bearer", "tok-missing") is None

    def test_revoke_removes_record(self):
        store = TokenStore()
        store.register("bearer", "tok-y", actor="alice", scope="admin")
        assert store.revoke("bearer", "tok-y") is True
        assert store.lookup("bearer", "tok-y") is None
