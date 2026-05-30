# keychain

A thin gateway layer that fronts a fleet of large language model inference endpoints. The runtime accepts inbound requests, verifies presented credentials against a token store, applies per-key rate limits, records auth attempts to an audit log, and forwards approved traffic to the upstream model pool.

## Modules

- `keychain.proxy` — `AuthHelper` resolves a presented credential to a principal record before forwarding.
- `keychain.request_handler` — `RequestHandler` reads a Bearer token off the incoming request and looks up the matching verification token row in the local store.
- `keychain.audit_emitter` — `AuthEventLog.record_auth_event` writes one tab-separated record per auth attempt into the runtime audit stream.
- `keychain.rate_limiter` — `RateLimiter` tracks active key usage and request timestamps for downstream backpressure decisions.
- `keychain.token_store` — in-memory store of token records used by `AuthHelper.resolve_principal`.

## Test layout

Baseline behavior tests live under `tests/test_keychain_baseline.py`.

## Provenance

Inspired by CVE-2026-42208 (BerriAI LiteLLM pre-auth SQL injection in the API key verification path; added to CISA KEV May 8 2026 after observed exploitation within 36 hours of the GitHub advisory). The keychain implementation is a structural port that lifts the compound failure pattern (untrusted credential into f-string SQL, audit pipeline that does not neutralize control bytes, per-class state shared across runtime instances, permissive auth method dispatch) without reproducing vendor-specific code.
