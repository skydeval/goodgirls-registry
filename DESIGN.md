# goodgirls.onl registry — rust port design doc

*version 1.0 — chrys + claude, 2026-04-17*

---

## 1. context

goodgirls.onl is a public custom-handle provider for the Bluesky/AT Protocol ecosystem. Users claim a subdomain of the form `{chosen}.goodgirls.onl`, bind it to their Bluesky DID, and configure Bluesky to use it as their handle. The service resolves `/.well-known/atproto-did` on each subdomain so that the AT Protocol network can verify the mapping.

The service is deliberately minimal. There are no accounts, no email addresses, no passwords, no recovery flows. When a user registers, they receive a **goodgirls key** — a 24-character random token — which is the only thing that authenticates future management. Lose the key, lose access. This is a feature, not a limitation.

The service is run by a single operator. The admin console is accessed through the same manage page as regular users — the admin key opens a different door than a user key. A configurable decoy endpoint exists as a honeypot that returns random mystical messages and leads nowhere.

The original implementation is a Cloudflare Worker using Workers KV for storage, written in JavaScript in October 2025. This document designs the Rust port.

---

## 2. goals and non-goals

### goals

1. **Exact functional parity with the worker.** Every endpoint the worker serves, the rust port serves. Every behavior a user or admin relies on today continues to work identically after cutover. No regressions.

2. **Mystical voice preservation.** The admin console's personality — "your registry spirit is humming quietly", "consulting the hidden ledger with your sigil", "the scissors slipped" — is the identity of this project. The rust port preserves every piece of that voice.

3. **Single-binary deployment.** One compiled binary, no runtime dependencies, no container, no interpreter. `scp` it to the box, restart the service, done.

4. **Sqlite over KV.** Cloudflare Workers KV is eventually-consistent and offers no querying beyond key lookup. Sqlite gives ACID transactions, proper indexing, and the ability to answer questions like "how many handles are registered" without scanning every key.

5. **Fix the bugs the worker has.** The worker allows handle theft via the manage endpoint, allows unlimited handle accumulation, deletes secrets prematurely, and has race conditions on registration. The rust port fixes all of these.

6. **Clean separation of concerns.** The worker is one file with inline HTML, CSS, JavaScript, and business logic all interleaved. The rust port separates routing, handlers, business logic, database access, and templates into distinct modules.

7. **Testability.** The worker has zero tests. The rust port has meaningful test coverage — at minimum, every user-facing endpoint and every admin endpoint.

### non-goals

1. **Multi-domain support.** This service serves `goodgirls.onl` only.

2. **PDS integration.** No proxy layer, no account creation, no signup flow.

3. **Pride themes.** Goodgirls has no theme system. The aesthetic is dark, minimal, purple accent.

4. **Application-level rate limiting.** Cloudflare sits in front and provides DDoS protection and rate limiting at the edge.

5. **Horizontal scaling.** One box, one process, one sqlite file.

6. **Automated monitoring or alerting.** The service is designed to be autonomous. No phone-home, no health endpoint, no SLA. If it goes down, the operator finds out by visiting the site. Documented as an intentional design choice.

---

## 3. data model

### worker (current)

Cloudflare Workers KV, flat key-value store:

- `{subdomain}` → `did:plc:...` (handle mapping)
- `secret:{did}` → SHA-256 hash of goodgirls key (secret storage)

Limitations: finding all handles for a DID requires scanning every key. No way to count handles without listing everything. No transactions, no indexes, eventual consistency.

### rust port

Sqlite, three tables:

```sql
CREATE TABLE IF NOT EXISTS handles (
    subdomain TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_handles_did ON handles(did);

CREATE TABLE IF NOT EXISTS secrets (
    did TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
```

The `idx_handles_did` index makes "find handle for a DID" and "check if DID has a handle" fast. No foreign key between handles and secrets — intentionally independent lifecycles. The sessions table holds at most one row (single admin, new login replaces old).

---

## 4. API surface

### public endpoints

**`GET /.well-known/atproto-did`** — Returns the DID for the subdomain in the `Host` header. Plain text response. This is the core AT Protocol endpoint that makes handle verification work. Only responds on subdomain requests (`{sub}.goodgirls.onl`), not the apex domain.

**`POST /register`** — Creates a new handle mapping.
- Accepts: `{subdomain, handle}`
- Resolves handle → DID via Bluesky API
- Validates subdomain (length, characters, reserved words, blocked keywords)
- Checks subdomain is not already taken
- Checks DID does not already have a handle (one per DID)
- Checks DID does not already have a secret (catches edge cases)
- Generates goodgirls key, stores SHA-256 hash, stores handle mapping
- Returns: `{ok, code, handle, did, goodgirls_key}`
- Admin mode: if `x-goodgirls-token` header matches admin key hash, bypasses the one-handle-per-DID check but still generates a key

**`GET /`** — Registration page. Dark, minimal, purple accent. Only served on the apex domain.

**`GET /manage`** — Manage page. Key-first flow: single input field for the goodgirls key. Only served on the apex domain.

**`POST /manage`** — The unified door.
- Accepts: `{key}` (initial authentication), or `{key, action, ...}` (authenticated action)
- SHA-256 hashes the input key
- Checks against admin key hash — if match, creates session, returns admin console
- Checks against secrets table — if match, looks up DID's current handle, returns manage/delete interface
- Neither matches — returns a random mystical camouflage message

**`POST /delete`** — Deletes the user's handle and secret.
- Accepts: `{key, confirm}`
- Requires `confirm: "DELETE"`
- Verifies key, finds DID, deletes the handle and the secret
- Always total deletion (one handle per DID, so delete means delete everything)

### admin endpoints (session-authenticated)

All admin endpoints require a valid session cookie and `X-CSRF-Token` header.

**`POST /api/admin/list`** — Returns all handle mappings, paginated. Supports forward and backward navigation.

**`POST /api/admin/wipe-did`** — Deletes all records for a DID: handle(s) and secret. The only admin delete operation — no per-subdomain admin delete.

**`POST /api/admin/export`** — Returns all handles and secrets as JSON for backup.

### decoy endpoint

**`GET {DECOY_PATH}`** — Serves a page that looks like it could be an admin login. Accepts POST with any body. Always returns a random mystical message. Never authenticates. Never leads anywhere. Logs the attempt (IP, timestamp) for operator awareness.

### subdomain routing

The rust service distinguishes apex requests from subdomain requests via the `Host` header:
- `goodgirls.onl` → serve pages and API endpoints
- `{sub}.goodgirls.onl` → only serve `/.well-known/atproto-did`, everything else returns 404

---

## 5. what the worker does well

Credit where it's due — built in a week by someone learning to code, October 2025:

1. **The key model is sound.** One secret per DID, hashed, never stored in plaintext, returned exactly once at registration. Simple and correct.

2. **The admin console has personality.** "Your registry spirit is humming quietly", "consulting the hidden ledger with your sigil", "the void accepts" — this is design philosophy, not decoration.

3. **Handle resolution is properly delegated.** Calls the Bluesky API's `resolveHandle` endpoint rather than trying to validate DIDs directly. Correct approach.

4. **The deletion model is thoughtful.** Requiring `confirm: "DELETE"` as a string prevents accidental API calls.

5. **Admin-mode registration is clean.** The `x-goodgirls-token` header path lets the operator assign handles without going through the normal flow.

6. **It ships and it works.** Production software serving real users. That matters more than any critique.

---

## 6. what the rust port improves and why

Each improvement traces back to a specific finding from the adversarial review (five passes, 53 total findings).

### 6.1 subdomain validation (pass 1, finding 1)

**Before:** No validation. Any string accepted as a subdomain.

**After:** Lowercase ASCII alphanumeric plus hyphens. No leading/trailing/consecutive hyphens. Minimum 3 characters, maximum 49 characters (63 minus `.goodgirls.onl` = 14 characters). Reserved word list: `admin`, `root`, `administrator`, `moderator`, `support`, `abuse`, `postmaster`, `webmaster`, `localhost`, `goodgirls`. Blocked keyword list for slurs — subdomains containing any blocked substring are rejected. The blocked list is a hardcoded constant in the binary. If a term slips through, the admin can wipe the handle immediately; adding the term to the list requires a recompile.

### 6.2 one handle per DID (pass 2, finding 2; refined in pass 5)

**Before:** A DID could accumulate unlimited handles. The manage endpoint was functionally a second registration endpoint that could overwrite other users' handles.

**After:** One handle per DID. Registration checks both subdomain availability and whether the DID already has a handle. Manage is a rename operation: delete the old mapping, write the new one, same transaction. Delete is always total: remove the handle and the secret. No orphaned handles, no accumulation, no theft.

### 6.3 ownership verification on manage (pass 1, finding 3)

**Before:** The manage endpoint verified the key but didn't check whether the target subdomain belonged to the caller's DID. Alice could steal Bob's handle.

**After:** Manage is a rename — it replaces the caller's own handle with a new subdomain. The caller never specifies which handle to change; the system looks it up from their DID. No possibility of overwriting another user's mapping.

### 6.4 safe secret deletion (pass 1, finding 6)

**Before:** Deleting a specific subdomain also deleted the secret, orphaning any other subdomains for that DID.

**After:** One handle per DID eliminates this entirely. Delete removes the one handle and the one secret. No partial states possible.

### 6.5 key-first manage flow (pass 5, discussion)

**Before:** The manage page asked for handle, key, and new subdomain simultaneously. Redundant inputs.

**After:** Single input: the goodgirls key. The system hashes it, identifies the DID, finds the current handle, and presents options (rename or delete). One field, full control. The same field also serves as the admin entry point — the admin key opens the admin console instead of the handle manager.

### 6.6 unified door with decoy (pass 5, discussion)

**Before:** Admin console at a hardcoded `/gg` path. Discoverable by guessing.

**After:** Admin access is through the manage page's key field. No separate admin URL to discover. A configurable decoy endpoint exists as a honeypot — serves a page that looks like it could be an admin login, always returns random mystical messages regardless of input, never authenticates, logs pokes for operator awareness.

### 6.7 non-enumerating failures (pass 4, finding; refined in pass 5)

**Before:** Error messages indicated what went wrong ("wrong key", "no goodgirls key exists", etc.).

**After:** Failed key submissions on the manage page return a random mystical message from a pool that includes both warm and cold messages: "the garden remembers your footsteps", "patience is a thread worth pulling", "the sigil does not resonate", "something stirs beneath the threshold", "a familiar warmth passes through", "not all doors open the same way." An attacker cannot distinguish failure from decorative page behavior.

### 6.8 session-based admin auth (pass 2, finding 4; refined through passes 3-5)

**Before:** Admin token stored in a JS variable for the page's lifetime. No session management, no CSRF protection.

**After:** Successful admin key entry creates a server-side session. `HttpOnly; SameSite=Strict; Secure` cookie. CSRF token stored in the session row, returned at login, required as `X-CSRF-Token` header on all admin POSTs. Single session — new login replaces old. Session cleanup happens on login (delete all existing rows before inserting new one). The admin key leaves the client's memory immediately after the initial POST.

### 6.9 consistent error responses (pass 1, finding 13; pass 4, finding 7)

**Before:** Inconsistent response shapes. `code` field only on one error.

**After:** Every response has a uniform shape: `{ok, code, ...}`. Success: `{ok: true, code: "registered", ...}`. Error: `{ok: false, code: "subdomain_taken", error: "that handle is already claimed"}`. Codes are a rust enum covering both success and error variants.

### 6.10 two-layer admin messaging (pass 4, finding 9)

**Before:** Admin console status messages were purely mystical. "The scissors slipped" doesn't help debugging at 3am.

**After:** Inside the authenticated admin space, every status message has two layers: the mystical copy stays as the primary text, followed by the raw technical detail. "The scissors slipped — `DELETE handles WHERE did = 'did:plc:abc' returned 0 rows`." The mystical layer is personality; the technical layer is debuggability.

### 6.11 key generation: rejection sampling (pass 1, finding 10)

**Before:** `arr[i] % chars.length` with modulo bias. Characters 0-15 slightly more likely than 16-29.

**After:** Rejection sampling: discard bytes ≥ 240, retry up to 10 times per position. Eliminates bias entirely. Same 30-character alphabet (`abcdefghjkmnpqrstuvwxyz23456789`) preserved for readability.

### 6.12 race condition elimination (pass 1, finding 15)

**Before:** KV has no transactions. Concurrent registrations for the same DID could generate conflicting keys.

**After:** Sqlite `BEGIN IMMEDIATE` transactions. The check-and-write for registration (is subdomain taken? does DID have a handle? does DID have a secret?) and the insert are atomic. Second request blocks until first completes, then sees the existing state and rejects.

### 6.13 structured logging (pass 3, finding 8)

**Before:** No logging at all.

**After:** `tracing` crate. Every registration, manage, delete, admin action, and error is logged with structured fields (subdomain, DID, timestamp, action type, error code). Upstream Bluesky API failures logged distinctly from application errors. Stdout, captured by systemd journal.

### 6.14 upstream resilience (pass 4, finding 1)

**Before:** No timeout on the Bluesky API call. If `resolveHandle` hangs, the request hangs.

**After:** 5-second timeout on the upstream fetch. Clear error message when Bluesky's API is unavailable. Distinct log entries for upstream failures vs application errors. No automatic retry — user can retry themselves.

### 6.15 entropy assertion (pass 4, finding 2)

**Before:** The security argument for SHA-256 (key has ~122 bits of entropy) was coupled to implementation details in a different function with nothing enforcing the coupling.

**After:** A test that computes the entropy of the key space (`key_length * log2(alphabet_size)`) and asserts it's above 100 bits. If anyone shortens the key or shrinks the alphabet, the test fails with a message explaining the SHA-256 decision depends on minimum entropy.

### 6.16 version from Cargo.toml (pass 1, finding 11)

**Before:** Manual `const VERSION = "0.95"` duplicated in two places.

**After:** `env!("CARGO_PKG_VERSION")` as single source of truth. Injected into the admin console template.

---

## 7. file structure

```
goodgirls-registry/
├── Cargo.toml
├── DESIGN.md                 # this document
├── .env.example
├── .gitignore
├── migrations/
│   └── 0001_init.sql
├── src/
│   ├── main.rs               # config, db pool, server startup
│   ├── routes.rs              # axum router definition
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── public.rs          # register, well-known, decoy
│   │   └── manage.rs          # key-first manage flow + admin console
│   ├── service.rs             # business logic
│   ├── db.rs                  # sqlite queries
│   ├── atproto.rs             # handle resolution via bluesky API
│   ├── validate.rs            # subdomain rules, reserved words, slur list
│   ├── auth.rs                # SHA-256 hashing, session management, CSRF
│   └── error.rs               # error types, consistent response shape
├── templates/
│   ├── index.html             # registration page
│   ├── manage.html            # key-first manage page
│   └── admin.html             # admin console (served after session auth)
└── tests/
    └── integration.rs
```

No theme module, no rate limiter, no separate config module. Simpler than anarchy by design.

---

## 8. deployment plan

### infrastructure

OVH VPS-1, 4 vCPU / 8GB RAM, Ubuntu 24.04, hostname "portfolio", IP 40.160.227.105. Shared caddy instance with anarchy. Cloudflare in front.

### service isolation

Dedicated system user:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin goodgirls
```

Directory structure:

```
/opt/goodgirls-registry/
├── goodgirls-registry          # the binary
├── .env                        # config
├── data/
│   └── registry.db             # sqlite database
└── backups/                    # cron backup target
```

Ownership: `goodgirls:goodgirls` on everything under `/opt/goodgirls-registry/`.

### systemd service

```ini
[Unit]
Description=goodgirls.onl handle registry
After=network.target

[Service]
Type=simple
User=goodgirls
Group=goodgirls
WorkingDirectory=/opt/goodgirls-registry
EnvironmentFile=/opt/goodgirls-registry/.env
ExecStart=/opt/goodgirls-registry/goodgirls-registry
Restart=on-failure
RestartSec=5

# hardening
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/goodgirls-registry/data
PrivateTmp=yes
NoNewPrivileges=yes
```

### caddy

```
*.goodgirls.onl, goodgirls.onl {
    reverse_proxy 127.0.0.1:3001

    header -Server
    header -X-Powered-By
}
```

Port 3001 (anarchy uses 3000). TLS via Cloudflare origin cert at `/etc/caddy/certs/`.

### cloudflare

- DNS for `goodgirls.onl` pointed at portfolio box IP, proxied (orange cloud)
- Wildcard `*.goodgirls.onl` CNAME → `goodgirls.onl`, proxied
- SSL mode: full (strict) with Cloudflare origin cert on caddy

### environment variables

```
DATABASE_URL=sqlite:///opt/goodgirls-registry/data/registry.db
ADMIN_KEY_HASH=your-sha256-hex-hash-here
BASE_DOMAIN=goodgirls.onl
LISTEN_ADDR=127.0.0.1:3001
DECOY_PATH=/gg
```

Five variables. The admin key hash is generated by the operator: `echo -n "your-chosen-key" | sha256sum`.

### backups

```bash
# /etc/cron.d/goodgirls-backup
0 4 * * * goodgirls cp /opt/goodgirls-registry/data/registry.db /opt/goodgirls-registry/backups/registry-$(date +\%Y\%m\%d).db && find /opt/goodgirls-registry/backups -name "registry-*.db" -mtime +7 -delete
```

Daily at 4am, keep last 7 days. Plus OVH nightly VPS-level backup.

### deploy flow

```bash
# build (WSL)
cd ~/goodgirls-registry
cargo build --release

# deploy
scp target/release/goodgirls-registry ubuntu@portfolio:/tmp/
ssh portfolio
sudo systemctl stop goodgirls-registry
sudo cp /tmp/goodgirls-registry /opt/goodgirls-registry/
sudo chown goodgirls:goodgirls /opt/goodgirls-registry/goodgirls-registry
sudo systemctl start goodgirls-registry
```

---

## 9. cutover plan

### pre-cutover

1. Rust service deployed and tested against seed data on the portfolio box
2. Caddy configured, origin cert in place
3. All existing handles exported from Cloudflare Worker KV via the worker's `/gg/api/list` endpoint (paginated)
4. Handle mappings imported into sqlite `handles` table
5. Secret hashes imported into sqlite `secrets` table (strip `secret:` prefix from KV keys, values are already SHA-256 hashes — directly portable, no rehashing needed)
6. Verify imported data: count matches, spot-check specific handles

### cutover

7. Flip Cloudflare DNS from Worker route to portfolio box IP
8. Purge Cloudflare cache
9. Verify: `/.well-known/atproto-did` resolves for existing handles
10. Verify: registration works (new handle)
11. Verify: manage works (rename existing handle)
12. Verify: delete works
13. Verify: admin access via manage page key field
14. Verify: decoy endpoint returns mystical messages

### post-cutover

15. Monitor for user reports (check Bluesky mentions/DMs)
16. After 48h with no issues, decommission the Cloudflare Worker
17. After 7 days, delete the Worker and KV namespace

---

## 10. verification checklist

How we know the port is done.

### protocol compliance

- [ ] `GET /.well-known/atproto-did` on `{sub}.goodgirls.onl` returns the correct DID
- [ ] `GET /.well-known/atproto-did` on `goodgirls.onl` (no subdomain) returns 400
- [ ] Non-existent subdomain returns 404
- [ ] Bluesky can verify a handle registered through the rust port

### registration

- [ ] Valid registration returns handle, DID, and goodgirls key
- [ ] Key is 24 characters from the correct 30-character alphabet
- [ ] Key hash is stored in `secrets` table, key is not stored anywhere
- [ ] Subdomain validation rejects: too short (<3), too long (>49), invalid characters, leading/trailing/consecutive hyphens, reserved words, blocked keywords
- [ ] Duplicate subdomain is rejected
- [ ] DID that already has a handle is rejected with message directing to manage page
- [ ] DID that already has a secret (no handle) is rejected with appropriate message
- [ ] Admin-mode registration via `x-goodgirls-token` header works and generates a key
- [ ] Concurrent registration attempts for the same DID don't produce conflicting state

### manage (key-first flow)

- [ ] Entering a valid user key shows the user's current handle with rename and delete options
- [ ] Entering the admin key loads the admin console
- [ ] Entering an invalid key returns a random mystical camouflage message
- [ ] Rename: old subdomain mapping is deleted, new one is created, same transaction
- [ ] Rename validates the new subdomain (same rules as registration)
- [ ] Rename rejects if the new subdomain is already taken by another DID

### delete

- [ ] Valid key + `confirm: "DELETE"` deletes the handle and the secret
- [ ] Missing or wrong `confirm` string is rejected
- [ ] After deletion, the DID can register a fresh handle

### admin console

- [ ] Session cookie is set on successful admin key entry
- [ ] Session is `HttpOnly; SameSite=Strict; Secure`
- [ ] CSRF token is required on all admin POSTs
- [ ] New admin login replaces the existing session (single session)
- [ ] List shows all handle mappings with pagination
- [ ] Wipe-DID removes all handles and the secret for a DID
- [ ] Export returns all data as JSON
- [ ] Admin status messages include mystical text AND technical detail
- [ ] Version badge shows `Cargo.toml` version

### decoy endpoint

- [ ] `GET {DECOY_PATH}` serves a page that looks like a login
- [ ] `POST {DECOY_PATH}` with any body returns a random mystical message
- [ ] Decoy never authenticates, never redirects, never reveals system state
- [ ] Decoy logs the attempt (IP, timestamp)

### subdomain routing

- [ ] Requests to `goodgirls.onl` (apex) serve pages and API endpoints
- [ ] Requests to `{sub}.goodgirls.onl` only serve `/.well-known/atproto-did`
- [ ] All other paths on subdomain requests return 404

### security

- [ ] Failed manage submissions are non-enumerating (same mystical message pool)
- [ ] No timing difference between "admin key wrong" and "user key wrong" and "key doesn't exist"
- [ ] SHA-256 key entropy test asserts minimum 100 bits
- [ ] Key generation uses rejection sampling (no modulo bias)
- [ ] Error responses never reveal whether a key, DID, or subdomain exists in the system (outside authenticated flows)

### operational

- [ ] Structured logging: registrations, manages, deletes, admin actions, errors, upstream failures
- [ ] Upstream Bluesky API timeout at 5 seconds with clear error message
- [ ] Systemd service starts, stops, restarts cleanly
- [ ] Service runs as dedicated `goodgirls` system user
- [ ] Service cannot read files outside `/opt/goodgirls-registry/data`
- [ ] Backup cron creates daily copies, retains 7 days

### cutover-specific

- [ ] All existing worker handles resolve correctly after import
- [ ] All existing user keys still work after import (SHA-256 hashes portable)
- [ ] No user action required during cutover

---

## 11. decision log

Consolidated record of every design decision, traced to the roast finding that motivated it.

| # | Decision | Finding | Rationale |
|---|----------|---------|-----------|
| D1 | Subdomain validation: 3-49 chars, alphanumeric + hyphens, reserved words, blocked keywords | P1-F1, P2-F1 | Worker accepted any string. DNS labels have rules. Slurs shouldn't be registrable. |
| D2 | SHA-256 for all secret hashing (user keys and admin key) | P1-F2, P4-F2 | ~122 bits of key entropy makes brute-force infeasible. Entropy assertion test enforces the coupling. |
| D3 | One handle per DID. Manage is rename, delete is total. | P1-F3, P1-F4, P1-F6, P2-F2 | Worker accidentally allowed accumulation and handle theft. One-per-DID eliminates both. |
| D4 | Key-first manage flow. One input, two destinations. | P5-F2, discussion | Simpler UX. Key is the only identity. System looks up everything else. |
| D5 | Unified door: admin key and user keys share the manage page input | P4-F10, P5-F5, discussion | No discoverable admin path. Admin surface is invisible to attackers. |
| D6 | Configurable decoy endpoint as honeypot | P5-F5, discussion | Returns random mystical messages. Logs pokes. Never authenticates. Wastes attacker time. |
| D7 | Non-enumerating failures with mystical camouflage | P4-F9, P5-F5 | Mixed warm/cold messages. Attacker can't distinguish auth failure from decorative page. |
| D8 | Server-side session, single row, new login replaces old | P2-F4, P3-F2, P3-F3, P5-F4 | One admin, one session. Login is cleanup. CSRF token in session row. |
| D9 | Consistent `{ok, code, ...}` response shape, success and error | P1-F13, P4-F7 | Uniform contract. Codes are a rust enum. No future breaking change. |
| D10 | Rejection sampling for key generation | P1-F10 | Eliminates modulo bias. Capped at 10 retries per position. |
| D11 | Version from `Cargo.toml` via `env!("CARGO_PKG_VERSION")` | P1-F11 | Single source of truth. No manual duplication. |
| D12 | Admin per-subdomain delete removed. Only wipe-DID. | P1-F8 | Per-subdomain delete created inconsistent state. One operation, clean semantics. |
| D13 | Admin registration generates a key | P1-F5 | No special "admin-managed" category. Admin delivers the key manually. Accepted trust boundary. |
| D14 | Structured logging via `tracing` | P3-F8 | Zero logging in the worker. Every action and error logged with structured fields. |
| D15 | No health endpoint | P3-F9, P5-F7 | Intentional. No monitoring, no SLA. Operator checks manually. Avoids information leakage. |
| D16 | 5-second timeout on Bluesky API calls | P4-F1 | Upstream dependency with no SLA. Timeout prevents hanging. Clear error messaging. |
| D17 | Two-layer admin messaging: mystical + technical | P4-F9 | Personality preserved, debuggability added. Only inside authenticated admin space. |
| D18 | Dedicated system user per service, systemd hardening | P4-F8, P5-F6 | Isolation without Docker overhead. `ProtectSystem=strict`, `ReadWritePaths`, `NoNewPrivileges`. |
| D19 | Subdomain-only routing for `/.well-known/atproto-did` | P4-F6 | Apex serves pages. Subdomains only serve the well-known endpoint. Everything else 404s. |
| D20 | Manage page copy explicitly states rename replaces the old handle | P5-F1 | Users must understand the old name is released. No ambiguity. |
| D21 | No argon2id anywhere. SHA-256 for everything. | P5-discussion | Admin key is operator-chosen but verified for sufficient entropy before hashing. One hash algorithm, no extra dependency. |
| D22 | Backup: OVH nightly + cron daily copy + admin export | P3-F10 | Three layers. Automated, manual, and API-accessible. 7-day retention on cron copies. |

---

*This document was adversarially reviewed in five passes with 53 total findings. The design stopped moving structurally on pass three; passes four and five were tightening and operational hardening. Every decision traces to a specific finding. The original worker was built in October 2025; this design document was written in April 2026, reflecting six months of growth in engineering practice.*
