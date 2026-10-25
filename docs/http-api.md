# Payroof API · HTTP reference

Every route, request and response of the Payroof API. For running it, see the
[README](../README.md).

## Contract at a glance

`P` means a Project-scoped `Authorization: Bearer <token>` header. `S` means
`Authorization: Bearer <poll_secret>`, **not** a Project token.

| Method | Route | Authorization | Success |
|---|---|---|---|
| GET | `/healthz` | none | 200 |
| GET | `/readyz` | none | 200 |
| GET | `/v1/altcha?purpose=project\|pairing\|recovery` | none | 200 |
| POST | `/v1/projects` | ALTCHA `project` | 201 |
| GET | `/v1/projects/{project}` | P, any permission | 200 |
| PUT | `/v1/projects/{project}/references/{reference}` | P, `references` | 201 new / 200 existing |
| GET | `/v1/projects/{project}/paths` | P, `paths` | 200, plain text |
| GET | `/v1/projects/{project}/access` | P, `access` | 200 |
| POST | `/v1/projects/{project}/access` | P, `access` | 201 |
| DELETE | `/v1/projects/{project}/access/{id}` | P, `access` | 204 |
| GET | `/v1/projects/{project}/webhooks` | P, `webhooks` | 200 |
| POST | `/v1/projects/{project}/webhooks` | P, `webhooks` | 201 |
| DELETE | `/v1/projects/{project}/webhooks/{id}` | P, `webhooks` | 204 |
| POST | `/v1/pairings` | ALTCHA `pairing` | 201 |
| GET | `/v1/pairings/{id}` | none: metadata | 200 |
| PUT | `/v1/pairings/{id}` | P, `access`, **empty body** | 204 |
| POST | `/v1/pairings/{id}/token` | S: one-use retrieval | 200 / 202 pending |
| POST | `/v1/recovery` | ALTCHA `recovery` | 200 |
| PUT | `/v1/recovery/{id}` | Ed25519 signature | 200 |

Exactly four immutable permissions exist: `references`, `paths`, `webhooks`,
`access`. Initial and recovered credentials have all four. Delegated credentials
are issued through Pairing.

JSON bodies require `Content-Type: application/json`. Unknown request fields are
rejected. Examples use placeholders for generated values and abbreviate ALTCHA
`parameters` as `{}` in request examples: fill it with the entire issued object.
Binary keys and signatures
use base64url without padding. Dates use RFC3339 UTC, while durations are seconds.
Responses have `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and
`X-Request-ID`. A 204 has no response body.

### Health and proof of work

`GET /healthz` → `{"alive":true}`. `GET /readyz` → `{"ready":true}` only when the
database, all configured scanners, and delivery worker are healthy and current;
otherwise 503 `worker_unready`. Liveness alone does not mean scanning is operational.

`GET /v1/altcha?purpose=project` returns an ALTCHA challenge, for example:

```json
{"parameters":{"algorithm":"PBKDF2/SHA-256","cost":5000,"data":{"purpose":"project"},"expiresAt":1890000000,"keyLength":32,"keyPrefix":"...","nonce":"...","salt":"..."},"signature":"..."}
```

Use an ALTCHA-compatible solver and return the **unchanged challenge** and solution:

```json
{"challenge":{"parameters":{"...":"exact issued parameters"},"signature":"..."},"solution":{"counter":42,"derivedKey":"..."}}
```

This object is the `altcha` field below. Challenges expire in 120 seconds, are
purpose-bound and durably single-use. Optional ALTCHA fields must be preserved.
`solution.time` is optional.

### Projects

`POST /v1/projects`:

```json
{"project":"my-store","recovery_key":{"algorithm":"ed25519","public_key":"<32-byte key>"},"watch_roots":[{"family":"eip155","path":"m/44'/60'/0'/1","key":{"algorithm":"bip32-secp256k1","public_key":"<33-byte compressed SEC1 key>","chain_code":"<32 bytes>"}}],"altcha":{"challenge":{"parameters":{},"signature":"..."},"solution":{"counter":42,"derivedKey":"..."}}}
```

→ `{"project":"my-store","token":"prf_...","permissions":["references","paths","webhooks","access"]}`

Currently exactly one `eip155` root is supported, shared across configured EVM
chains. Its path must be `m/44'/60'/<canonical slot>'/1`, with slot below 2³¹: payment
addresses get a branch of their own, apart from the account's addresses (`…'/0/<index>`),
so nothing else the merchant receives is taken for a payment.
The recovery public key must be a nonweak Ed25519 key. Keep its private key offline.
Recovery keys and watch material cannot be registered twice (even under another
name/path). Project names are 1–63 lowercase ASCII letters/digits/hyphens and
start and end alphanumeric.
Project names are labels, not credentials: authorization comes only from the bearer token.

`GET /v1/projects/my-store`:

```json
{"project":"my-store","watch_roots":[{"family":"eip155","path":"m/44'/60'/0'/1","fingerprint":"sha256:..."}],"chains":[{"id":"eip155:1","name":"Ethereum","confirmations":12,"assets":[{"id":"eip155:1/slip44:60","symbol":"ETH","decimals":18}]}],"created_at":"2026-10-08T00:00:00Z"}
```

Deployment configuration defines chains, assets and confirmation rules.
The Project view exposes their public catalog and watch-root fingerprints.

| Blockchain family | Support |
|---|---|
| `eip155` | EVM native assets and ERC-20 tokens |
| Bitcoin, Tron, TON | Future adapters, not implemented |

`watch_roots[]`, `family`, namespaced chain/asset identifiers and `destinations[]`
are the extension boundary. Every destination contains only `chain` and `address`.

### References and paths

`PUT /v1/projects/my-store/references/ORDER-42`, empty body:

```json
{"project":"my-store","reference":"ORDER-42","destinations":[{"chain":"eip155:1","address":"0x..."},{"chain":"eip155:137","address":"0x..."}]}
```

References are case-sensitive opaque identifiers (1–128 ASCII letters/digits or
`-._~`). Allocation is atomic and idempotent within a Project. Repeating
a reference returns the same address. Internal indexes are never exposed here.

Every project is watched for exactly the assets in the deployment configuration;
projects cannot add any. `GET /v1/projects/my-store` lists each configured chain
with its assets.

`GET /v1/projects/my-store/paths?scope=confirmed&limit=200&cursor=<opaque>` returns
`text/plain; charset=utf-8`, **not JSON**:

```text
m/44'/60'/0'/1/0
m/44'/60'/0'/1/2
```

`scope` is `confirmed` (default) or `all`. Default limit is min(200, configured
page cap), maximum configured cap ≤1000. The response includes
`Payroof-Next-Cursor: <opaque>` and `Payroof-Has-More: true|false`, even on empty
pages. Preserve the cursor for the next request. It is authenticated and bound
to Project and scope. `all` enumerates allocations. `confirmed` enumerates paths
that have received confirmed transfers. Entries may have index gaps.

### Access

`GET /v1/projects/my-store/access` lists the live credentials, ordered by creation:

```json
{"access":[{"id":"acc_...","name":"First wallet","permissions":["references","paths","webhooks","access"],"created_at":"2026-10-08T00:00:00Z"}]}
```

Revoked credentials are not listed and bearer secrets are never included.
`DELETE /v1/projects/my-store/access/acc_...` permanently revokes that credential
(204, idempotent). Unknown IDs and IDs of other Projects return 404. Both routes
require `access`.

`POST /v1/projects/my-store/access` with `{"name":"Cashier","permissions":["references","paths"]}`
issues a credential (201):

```json
{"id":"acc_...","name":"Cashier","permissions":["references","paths"],"created_at":"2026-10-08T00:00:00Z","token":"prf_..."}
```

The `token` is returned only in this response and is never listed. `name` is
1-100 bytes with no control characters or surrounding whitespace.
`permissions` must be non-empty, duplicate-free, and a subset of the caller's own
permissions; otherwise 403 `permission_denied`. Malformed bodies, unknown fields
or unknown permissions return 400 `invalid_json`; invalid names or permission
sets return 400 `invalid_name` / `invalid_permissions`. Credentials are also
issued by Project creation, pairing retrieval, and recovery.

### Pairing: one resource, two actors

```text
Requester POST /v1/pairings → id + poll_secret + url
Wallet    GET  url         → inspect untrusted name + requested permissions
Wallet    PUT  url (P)     → explicitly approve for the token's Project, no body
Requester POST url/token (S) → pending, or retrieve exactly one requested token
```

`POST /v1/pairings`:

```json
{"name":"Store integration","permissions":["references","webhooks"],"altcha":{"challenge":{"parameters":{},"signature":"..."},"solution":{"counter":42,"derivedKey":"..."}}}
```

→ `{"id":"pair_...","poll_secret":"pairsec_...","url":"https://api.payroof.top/v1/pairings/pair_...","expires_in":300,"interval":5}`

Names follow the same rules as access credential names (1–100 bytes, no control
characters or surrounding whitespace). Permissions must be a nonempty, duplicate-free subset
of the four permissions. Treat the name as **untrusted text**, not an identity.
Viewing the URL does not approve or retrieve anything. `GET` returns:

```json
{"id":"pair_...","name":"Store integration","permissions":["references","webhooks"],"status":"pending","expires_at":"2026-10-08T00:05:00Z"}
```

`PUT` requires a live Project credential with `access`, infers the Project from that
token, and accepts no body or Project selector. Only pending, unexpired requests
can be approved. Decline by not approving.

With the poll secret as bearer, `POST /v1/pairings/{id}/token` returns 202
`{"status":"pending","retry_after":5}` with `Retry-After: 5`, or 200:

```json
{"status":"approved","project":"my-store","token":"prf_...","permissions":["references","webhooks"]}
```

Poll no faster than every five seconds. An invalid poll secret returns 401.
The poll secret is returned only at creation and stored hashed.
Retrieval is transactional and single-use, and the approving token must still
be live. Pairing issues **a credential with exactly the requested permissions**.
Metadata status may subsequently be `approved` or `consumed`.

### Recovery

`POST /v1/recovery` begins recovery for the Project of a recovery key. A key owns at
most one Project, so the key alone selects it; an unknown key is `404 not_found`:

```json
{"recovery_key":{"algorithm":"ed25519","public_key":"<32-byte key>"},"altcha":{"challenge":{"parameters":{},"signature":"..."},"solution":{"counter":42,"derivedKey":"..."}}}
```

→ `{"id":"rcv_...","challenge":"<random base64url nonce>","expires_in":120}`

Sign these exact UTF-8 bytes with the corresponding Ed25519 private key, including
the final newline. Origin is the configured `origin`, or one of its configured
`origin_aliases`, **without trailing slash** (the one the client reached):

```text
payroof-recovery-v2\n<origin>\n<id>\n<challenge>\n
```

`PUT /v1/recovery/rcv_...` completes it (no bearer required):

```json
{"signature":"<64-byte Ed25519 signature>","name":"Recovered wallet"}
```

→ `{"project":"my-store","token":"prf_...","permissions":["references","paths","webhooks","access"]}`

Project and public key are loaded from the challenge, never selected at completion;
the Project's name is returned only here, after the signature proves the key.
Challenges are origin/Project-bound, expire after 120 seconds, and succeed once
even under concurrent requests. Existing credentials remain valid until revoked;
use the recovered token to inspect and revoke compromised access.

### Webhooks

`POST /v1/projects/my-store/webhooks`:

```json
{"url":"https://receiver.example/payroof","events":["seen","confirmed"]}
```

→ `{"id":"wh_...","url":"https://receiver.example/payroof","events":["seen","confirmed"],"secret":"whsec_..."}`

Store the secret immediately. It is returned once. Events must be nonempty and
unique, drawn from `seen` and `confirmed`. Maximum 10 webhooks per Project.
`GET /v1/projects/my-store/webhooks`:

```json
{"webhooks":[{"id":"wh_...","url":"https://receiver.example/payroof","events":["seen","confirmed"],"created_at":"2026-10-08T00:00:00Z"}]}
```

`DELETE /v1/projects/my-store/webhooks/wh_...` → 204. Unknown IDs →404. To change
URL/events, create the replacement subscription, then delete the existing one.

Delivery is POST JSON with `Payroof-Id`, `Payroof-Timestamp` (Unix seconds), and
`Payroof-Signature: v1=<hex HMAC-SHA256>`:

```json
{"id":"evt_...","event":"confirmed","transfer":"...","project":"my-store","reference":"ORDER-42","chain":"eip155:1","asset":"eip155:1/slip44:60","address":"0x...","transaction":"0x...","amount":"1000000000000000000","block":{"height":"12345","hash":"0x..."}}
```

`transfer` identifies the transfer across its `seen` and `confirmed` events. Amount is an integer in asset base units. Height is a decimal string. Decode the
base64url suffix of `whsec_` to 32 bytes and authenticate
`ASCII(timestamp) || "." || raw HTTP body`. Verify in constant time **before**
parsing, reject timestamps beyond ±300 seconds, and deduplicate `Payroof-Id`.
Delivery retries with bounded exponential backoff/jitter, up to 20 attempts.
Receivers should promptly return 2xx. Events are not an exactly-once settlement
guarantee. Reorgs and downstream business policy still matter.

## Public errors and security

Errors are JSON, including unmatched routes and method failures:

```json
{"error":"permission_denied","message":"permission denied","request_id":"req_..."}
```

| HTTP | Public codes |
|---|---|
| 400 | `invalid_json`, `invalid_request`, `invalid_purpose`, `invalid_altcha`, `invalid_project`, `invalid_recovery_key`, `unsupported_family`, `invalid_watch_root`, `invalid_reference`, `invalid_permissions`, `invalid_name`, `invalid_page`, `invalid_cursor`, `invalid_events`, `invalid_webhook_url`, `unexpected_body` |
| 401 | `unauthorized`, `invalid_signature` |
| 403 | `forbidden` (wrong Project), `permission_denied` |
| 404 | `not_found` |
| 405 | `invalid_request` (method not allowed) |
| 408 | `request_timeout` |
| 409 | `conflict`, `project_exists`, `watch_root_in_use`, `altcha_replayed`, `derivation_exhausted`, `pairing_unavailable`, `pairing_approver_revoked`, `webhook_limit` |
| 410 | `pairing_expired`, `pairing_consumed`, `recovery_challenge_expired`, `recovery_consumed` |
| 413 | `body_too_large` |
| 429 | `rate_limited`, `slow_down` (with `Retry-After: 5`) |
| 500 | `internal`, `persisted_data_invalid` |
| 503 | `database_unavailable`, `worker_unready`, `pairing_capacity` |

Framework query/path rejections retain their HTTP status and use `invalid_request`.
Use status/code rather than message text. Error responses never expose SQL, keys,
or stack traces. Request IDs support log correlation.

* Bearer tokens are opaque, hashed at rest, revocable, and Project-scoped. Path
  names do not authorize access. Permission corruption fails closed.
* Webhook secrets are encrypted at rest with per-webhook authenticated context.
* Production requires HTTPS origin/RPCs. Webhooks require HTTPS on port 443,
  public DNS addresses, no credentials/fragments, no redirects/proxy inheritance;
  every attempt validates DNS and pins the connection addresses against rebinding.
* Only configured native/ERC20 assets are scanned. Worker state and observed transfers
  are durable in SQLite. Canonical block checks handle reorgs.
* Public proof-of-work, durable replay protection, bounded bodies/concurrency,
  rate/capacity limits, and 15-second HTTP request deadlines are enforced.
* Only explicitly configured trusted proxy CIDRs can supply client IP forwarding.
  Do not log Authorization/poll secrets or expose untrusted names as HTML.
