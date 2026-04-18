# goodgirls.onl

a handle provider for bluesky. claim a `yourname.goodgirls.onl` handle, use it on your bluesky account. that's it.

## the story

goodgirls.onl was the first thing i ever built. october 2025, about 10 hours of work, no IDE, no CLI experience, no version control. just a cloudflare worker, workers KV, and a lot of copy-pasting until it compiled. it worked. people used it. handles resolved. that was enough.

six months later — april 2026 — i ported it to rust in about 8 hours as part of the [navigators guild apprentice program](https://github.com/Navigators-Guild/apprentice-onboarding) apprentice program. same problem, harder language, better result, less time. the design doc that precedes this code has five rounds of adversarial review and 53 findings. every decision traces to a specific weakness in the original worker.

this is the rust port. it runs on a single VPS, serves a single domain, and does one thing well.

## what it does

- users claim a `{name}.goodgirls.onl` handle for their bluesky account
- the service resolves `/.well-known/atproto-did` so the AT protocol can verify the handle
- users get a **goodgirls key** at registration — the only credential, returned once, never stored in plaintext
- one handle per DID. manage (rename) and delete are available to anyone with their key
- a single operator admin console, accessed through the same key field as regular users

## what the port improves

the original worker had real bugs and architectural gaps. the port fixes them:

- **handle theft via manage endpoint** — the worker let any authenticated user overwrite any subdomain. the port verifies ownership.
- **unlimited handle accumulation** — the worker let a single DID claim unlimited subdomains. the port enforces one handle per DID.
- **premature secret deletion** — the worker deleted the secret key when deleting a single subdomain, orphaning other handles for the same DID. the port's one-handle-per-DID model eliminates this class of bug entirely.
- **race conditions on registration** — workers KV has no transactions. the port uses sqlite with `BEGIN IMMEDIATE` transactions.
- **zero input validation** — the worker accepted any string as a subdomain. the port validates length (3–49 chars), character set, reserved words, and blocked keywords.
- **no logging** — the worker had none. the port logs every action with structured fields via `tracing`.
- **no tests** — the worker had zero. the port has 70 (57 unit + 13 integration).

the full list of 22 design decisions and their rationale is in [DESIGN.md](DESIGN.md).

## architecture

```
rust / axum / sqlite / caddy / cloudflare
```

single binary, no runtime dependencies. caddy handles TLS and reverse proxying. cloudflare handles DNS and edge protection. the binary serves HTML pages via askama templates and a JSON API for registration, management, and admin operations.

the admin console is not at a separate URL. the manage page's key field serves as a unified door — a user key opens handle management, the admin key opens the admin console. there is no discoverable admin path. a configurable decoy endpoint exists as a honeypot that returns random mystical messages and leads nowhere.

## file structure

```
goodgirls-registry/
├── Cargo.toml
├── DESIGN.md
├── .env.example
├── migrations/
│   └── 0001_init.sql
├── src/
│   ├── main.rs               # config, db pool, server startup
│   ├── lib.rs                 # module exports for tests
│   ├── routes.rs              # axum router
│   ├── state.rs               # shared application state
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── public.rs          # register, well-known, decoy
│   │   └── manage.rs          # key-first manage flow + admin
│   ├── service.rs             # business logic
│   ├── db.rs                  # sqlite queries
│   ├── atproto.rs             # bluesky handle resolution
│   ├── validate.rs            # subdomain rules
│   ├── auth.rs                # SHA-256, key generation, sessions
│   └── error.rs               # error types
├── templates/
│   ├── index.html             # registration page
│   ├── manage.html            # key-first manage page
│   └── admin.html             # admin console
└── tests/
    └── integration.rs
```

## setup

### prerequisites

- rust toolchain (build machine — WSL2 or native linux)
- a linux server with caddy and sqlite
- a domain with cloudflare DNS

### configuration

copy `.env.example` to `.env` and fill in the values:

```
DATABASE_URL=sqlite:///opt/goodgirls-registry/data/registry.db
ADMIN_KEY_HASH=your-sha256-hex-hash-here
BASE_DOMAIN=goodgirls.onl
LISTEN_ADDR=127.0.0.1:3001
DECOY_PATH=/gg
```

to generate your admin key hash:

```bash
echo -n "your-chosen-key" | sha256sum
```

take the hex string (without the trailing ` -`) and put it in `ADMIN_KEY_HASH`.

### build

```bash
cargo build --release
```

the binary is at `target/release/goodgirls-registry`.

### deploy

```bash
# create service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin goodgirls

# create directories
sudo mkdir -p /opt/goodgirls-registry/data
sudo mkdir -p /opt/goodgirls-registry/backups
sudo chown -R goodgirls:goodgirls /opt/goodgirls-registry

# copy binary and config
sudo cp target/release/goodgirls-registry /opt/goodgirls-registry/
sudo cp .env /opt/goodgirls-registry/
sudo chown -R goodgirls:goodgirls /opt/goodgirls-registry

# install and start the systemd service
sudo cp goodgirls-registry.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable goodgirls-registry
sudo systemctl start goodgirls-registry
```

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
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/goodgirls-registry/data
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

### caddy

```
*.goodgirls.onl, goodgirls.onl {
    reverse_proxy 127.0.0.1:3001
    header -Server
    header -X-Powered-By
}
```

### cloudflare

- A record: `goodgirls.onl` → your server IP (proxied)
- CNAME: `*.goodgirls.onl` → `goodgirls.onl` (proxied)
- SSL: full (strict) with origin cert on caddy

### backups

```bash
# /etc/cron.d/goodgirls-backup
0 4 * * * goodgirls cp /opt/goodgirls-registry/data/registry.db /opt/goodgirls-registry/backups/registry-$(date +\%Y\%m\%d).db && find /opt/goodgirls-registry/backups -name "registry-*.db" -mtime +7 -delete
```

## the aesthetic

goodgirls was always meant to feel different. the admin console doesn't say "error: database locked" — it says "the scissors slipped" and then tells you the database was locked. the manage page doesn't enumerate failures — it returns warm, ambiguous, mystical messages whether you typed the wrong key or the right one for a different door. there's a decoy endpoint that looks like it could be a login page and returns cryptic phrases no matter what you give it.

this isn't whimsy for its own sake. the mystical voice is a security feature (non-enumerating responses), a personality feature (the service feels like *something*), and a design philosophy (tools should have character). the name is "goodgirls.onl" — it was never going to be utilitarian.

## accessibility

all pages target WCAG 2.2 Level AA compliance, reaching for AAA where practical. this includes semantic HTML5, proper label associations, aria-live regions for all dynamic content, visible focus indicators, keyboard operability, skip-to-content links, and color contrast ratios that clear AA minimums across all text and interactive elements. two AAA criteria are intentionally unmet: enhanced target size (44×44) on inline copy buttons, and enhanced contrast (7:1) on the purple accent color. both clear AA thresholds comfortably.

## design doc

[DESIGN.md](DESIGN.md) contains the full design document: context, goals, data model, API surface, five adversarial review passes with 53 findings, and a decision log mapping every design choice to the finding that motivated it. if you want to understand *why* something works the way it does, that's where to look.

## retrospective

the original registry was my first project ever. it took me 10 hours to build, using ChatGPT alone. i learned a lot in that because i'd gone from an idea like "can i make this?" to producing a functional website in that time. and in the seven months since, i've been working on larger projects, where revisiting this to port into rust left me wanting to make it better still somehow.

when i built it, like with the anarchy registry, i had not developed the non-enumeration strategy yet, so when it came to improving on this project in rust, it was a no-brainer to implement it somehow. but then i took it a step further by adding a decoy honeypot for potential hackers. the would-be admin login page, usually accessible at `/gg`, is a page with a login form which presents random messages from a pool, whether positive or negative; the purpose is almost to troll an attacker who might try to bypass security. so even if they manage to guess the password, they still get a random response, which tells them nothing about their attempt.

there wasn't anything that surprised me about the adversarial review process for improving code before committing to it, because i've been utilizing that strategy in my larger projects for months; what was new was running several passes — more than just two — to check for anything extra. i hadn't considered prior that after making changes it was a new field and there may be new problems introduced by the changes, so i made sure to run several passes with this port project to see what all could be found, and i kept going until no more structural problems were found and it was all about tightening.

## license

This project is not currently licensed for reuse. It's a personal portfolio piece and a live production service.
