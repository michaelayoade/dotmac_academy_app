# ERP applicant assessment integration contract (v1)

This document is normative for the Dotmac ERP client and Academy sender. The executable contract is in `app/api/erp_applicant_assessments.py`, `app/services/erp_integration_security.py`, `app/services/erp_applicant_assessments.py`, and `app/services/erp_assessment_sync.py`.

## ERP to Academy registration

### Transport and tenant

`POST /integrations/erp/applicant-assessments` on the configured HTTPS Academy tenant origin. Send `Content-Type: application/json`, `X-Webhook-Timestamp`, and `X-Webhook-Signature-256`.

Academy resolves the tenant from the trusted request host. The body is limited to 16,384 bytes. JSON must be UTF-8. Sign the exact bytes sent; do not parse and reserialize between signing and transmission.

### Authentication byte contract

Configuration:

- Academy verifier secret: `ERP_INBOUND_HMAC_SECRET`.
- Maximum clock skew: `ERP_INBOUND_HMAC_MAX_SKEW_SECONDS`, default 300 seconds.
- This secret must differ from outbound `ERP_WEBHOOK_SECRET`.

Headers and signature:

- `X-Webhook-Timestamp`: canonical, unsigned base-10 Unix time in whole UTC seconds. Digits only, no sign, whitespace, decimal point, or leading zero (except the value `0`).
- Preimage: `ASCII(timestamp) || 0x2e || exact_raw_HTTP_body_bytes`.
- Algorithm: HMAC-SHA256 with the UTF-8 bytes of `ERP_INBOUND_HMAC_SECRET` as key.
- Output: 64 lowercase hexadecimal digest characters.
- `X-Webhook-Signature-256`: exactly `sha256=<64-lowercase-hex>`.

Academy rejects a timestamp whose absolute difference from its current Unix time exceeds the configured skew. Comparison uses `hmac.compare_digest`. There is no nonce/replay cache: a byte-identical request can be replayed within the time window, and durable `external_ref` idempotency makes the replay non-creative.

Deterministic test vector:

```text
secret UTF-8: test-inbound-secret
timestamp: 1786089600
body bytes (one line, no final newline):
{"external_ref":"APP-42","email":"ada@example.com","first_name":"Ada","last_name":"Lovelace","return_url":"https://erp.example/recruitment/applications/APP-42"}
preimage bytes (one line, no final newline):
1786089600.{"external_ref":"APP-42","email":"ada@example.com","first_name":"Ada","last_name":"Lovelace","return_url":"https://erp.example/recruitment/applications/APP-42"}
X-Webhook-Signature-256: sha256=6e97bf8756317381db24f1377a872012cfb41f1969d1d1e5dcfe73fcaab5bc3c
```

The timestamp represents `2026-08-07T08:00:00Z`.

### Request JSON

The object is closed: unknown properties are rejected.

| Property | JSON type | Required | Constraints |
|---|---|---:|---|
| `external_ref` | string | yes | 1–64 characters, not blank, no C0 or DEL control characters; opaque and preserved exactly |
| `email` | string | yes | Pydantic `EmailStr`; normalized for Academy storage, never used as ERP application identity |
| `first_name` | string | yes | 1–80 characters, not blank; surrounding whitespace is removed for storage |
| `last_name` | string | yes | 1–80 characters, not blank; surrounding whitespace is removed for storage |
| `assessment_bank_id` | string | no | canonical parseable UUID; omit or JSON `null` for the tenant default |
| `return_url` | string | yes | 1–2048 characters and valid under the return policy below |

A usable bank is the tenant-scoped `QuestionBank.id` UUID and must contain at least one `Question`. It is a question-pool record tied to a course and carrying `kind` and integer `version`; Academy does not currently have a separate publish flag for banks. When omitted/null, Academy requires `Tenant.default_entrance_bank_id`; absence of that default is a 422 product/configuration error. The selected UUID is snapshotted on the applicant before the sitting.

`return_url` must be HTTPS, have a hostname, contain no credentials or fragment, and have an origin exactly present in comma-separated `ERP_ALLOWED_RETURN_ORIGINS`. Origin comparison lowercases the host and normalizes explicit port 443 away. Paths and query strings are permitted and preserved. The completion redirect uses the stored URL unchanged and appends no result data.

### Idempotency

`(tenant_id, external_ref)` is a durable partial unique database index for non-null external references. Registration uses PostgreSQL conflict handling followed by a row lock; simultaneous duplicates cannot create two Applicant rows or attempts.

For the first valid request Academy creates one `Applicant` with source `erp_live`, fixes its bank and return URL, and establishes a seven-day deadline. An identical retry while not expired returns HTTP 200 with the same deterministic assessment URL, expiry, and current state. The URL token is derived from the same Applicant and reset counter, so a lost response does not lose the credential.

The same `external_ref` with a different normalized email, bank, or return URL returns 409 `external_ref_conflict`. Names may be refreshed until the assessment starts; after start they remain the stored snapshot. A retry after invitation expiry returns 409 and does not create a replacement. An administrator must explicitly reset/reinvite; a reset increments the reset counter and the next registration URL is a new credential tied to the same Applicant.

### Success response

HTTP 200 for creation and idempotent replay:

```json
{
  "assessment_url": "https://academy.example/apply/assessment?token=<43-character-base64url-token>",
  "expires_at": "2026-08-14T08:00:00Z",
  "state": "not_started"
}
```

The exact response properties are `assessment_url` (absolute HTTPS URI string), `expires_at` (UTC RFC 3339 timestamp), and `state` (`not_started`, `in_progress`, or `completed`).

### Error response

All application errors use `{"error":{"code":"...","message":"..."}}`. Messages are safe summaries and are not a stable machine key; consume `code`.

| HTTP | Codes |
|---:|---|
| 400 | `malformed_json` |
| 401 | `missing_authentication`, `invalid_timestamp`, `stale_timestamp`, `invalid_signature` |
| 409 | `external_ref_conflict`, `registration_conflict`, `assessment_link_expired` |
| 413 | `request_too_large` |
| 422 | `invalid_request`, `unknown_assessment_bank`, `assessment_bank_required`, `invalid_return_url` |
| 500 | `internal_error` |
| 503 | `integration_disabled`, `integration_not_configured` |

Authentication is checked before JSON parsing. Authentication failures share the public message `Request authentication failed` and do not expose verifier details beyond the code.

## Assessment URL and browser completion

`assessment_url` uses the configured trusted `ACADEMY_PUBLIC_BASE_URL`, never the inbound Host header. The token is a 256-bit HMAC-SHA256 result encoded as unpadded URL-safe base64 (43 characters); it contains no PII, ERP secret, external reference, or predictable Applicant identifier. Academy stores only its existing HMAC token hash.

The URL is a bearer credential for one assessment sitting, not a one-HTTP-request link. It is reloadable and resumable, with autosaved answers, until its fixed seven-day invitation deadline. No Academy account or login is required. First explicit start fixes the server start time. After completion it cannot be submitted again and renders the already-completed state; after expiry it renders the closed state. A reset is the only supported replacement and keeps the same underlying Applicant while rotating the token.

Academy's request logger records only `request.url.path`, not the query string. Code must never log request bodies, `assessment_url`, or token values. Edge/proxy access logging must retain the same query-redaction property.

Submitting the assessment records the authoritative result transactionally, then returns HTTP 303 `Location: <return_url>` for normal browser requests or HTTP 204 with `HX-Redirect: <return_url>` for HTMX. The redirect carries no score or result. Server-side webhook production depends only on persisted completion state, not on the browser reaching the return URL.

## Academy to ERP completion event

The existing hourly `academy-erp-training-sync.timer` invokes the same state-derived sweep used by course completions. A completed, unsynced `erp_live` Applicant produces this closed v1 object:

```json
{
  "assessment_bank_id": "e3bc7ba7-c9d0-4660-a5fb-39b4b04df452",
  "completed_at": "2026-08-07T12:30:15.123456Z",
  "event_id": "entrance-assessment:9ba3a52f-eac9-4d9a-8aa2-8e523311554c:v1",
  "event_type": "entrance_assessment_completed",
  "external_ref": "APP-42",
  "invalid_reason": null,
  "is_valid": true,
  "level": "advanced",
  "profile": {"aptitude": 0.75, "safety": 1.0},
  "result_version": 1,
  "score": 0.82,
  "time_exceeded": false,
  "valid_until": null,
  "version": 1
}
```

Properties and source semantics:

- `version`: integer literal `1` (event schema version).
- `event_type`: string literal `entrance_assessment_completed`.
- `event_id`: stable string for one result revision, `entrance-assessment:<Academy Applicant UUID>:v<result_version>`; ERP uses it for delivery deduplication.
- `external_ref`: exact opaque string registered by ERP. Email is absent and must not be used for matching.
- `assessment_bank_id`: canonical UUID string of the snapshotted QuestionBank.
- `result_version`: integer >= 1, monotonically increasing for this Applicant.
- `completed_at`: UTC RFC 3339 instant with `Z`; sourced from `Applicant.assessment_taken_at`.
- `score`: JSON number in [0.0, 1.0], overall weighted fraction rounded to at most four decimal places by grading; never null in this event.
- `level`: one of `beginner`, `intermediate`, `advanced`; default absolute bands are [0,0.4), [0.4,0.7), and [0.7,1.0]. A supported percentile rebanding operation can later revise it.
- `profile`: JSON object with 0–100 properties. Keys are Academy question category strings of length 1–40 (`general` is the fallback); ERP must allow previously unseen category keys. Values are JSON numbers in [0.0,1.0], rounded to at most four decimal places. Boolean, string, null, array, and object values are forbidden. No unknown top-level properties exist in v1.
- `is_valid`: boolean validity gate. `false` means the sitting is not usable signal, not merely a low score.
- `invalid_reason`: `null`, `near_chance`, or `too_fast`; it is null exactly when `is_valid` is true.
- `time_exceeded`: boolean indicating the configured sitting time plus grace was exceeded. It is distinct from the validity gate.
- `valid_until`: always JSON null in v1. Academy has no result-expiration policy; the invitation deadline is not result validity.

### Corrections, resets, and ERP precedence

Academy supports level correction through `recompute-entrance-levels` and a new result after an administrator resets and the applicant retakes. Either authoritative completed change increments `result_version`, clears the delivery marker, and emits another `entrance_assessment_completed` with a new `event_id`. There is no separate correction event. Direct/manual score regrading is not an Academy domain operation today. Reset alone emits no invalidation event; synchronization resumes when the new sitting completes.

ERP should deduplicate by `event_id`, retain the result having the greatest `result_version` for an `external_ref`, replace the stored authoritative result when a larger version arrives, treat the same version as a duplicate, and ignore an older version. It must not infer ordering from delivery time.

## Academy to ERP authentication and delivery

Configuration uses `ERP_WEBHOOK_URL` and outbound-only `ERP_WEBHOOK_SECRET`. The request is `POST` with `Content-Type: application/json` and `X-Webhook-Signature-256` exactly `sha256=<64 lowercase hex>`. There is no outbound timestamp header in the established protocol.

The body is UTF-8 JSON serialized with sorted keys, compact separators (`,` and `:`), and non-ASCII characters emitted as UTF-8. The signature preimage is exactly the raw body bytes, with no timestamp, prefix, suffix, separator, or newline. The algorithm is HMAC-SHA256 using UTF-8 secret bytes; output is lowercase hex with the `sha256=` prefix.

Each HTTP attempt has a 15-second timeout. Delivery is acknowledged only when the HTTP status is 2xx, the response body is readable JSON, and its top-level `status` is `recorded`, `updated`, or `duplicate`. `ignored` or `unsupported` (top-level or under `detail.status`) is unmatched; every non-2xx or other/missing/unreadable acknowledgement is failed.

Only an acknowledged event stamps `assessment_erp_synced_at`. All other outcomes remain pending and the systemd timer retries on its fixed hourly schedule, indefinitely, with no exponential backoff or attempt cap. Delivery is therefore at least once: an accepted response lost in transit causes a duplicate. Event records contain no secrets, and sender logs omit body, PII, external reference, and token; they record only internal Applicant ID, response status/outcome, or exception type.
