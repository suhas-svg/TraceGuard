# Configuration

Copy `.env.example` to `.env`. Every value also works as an environment
variable, which is how the compose file reads them.

| Variable | Used by | Default | Notes |
|---|---|---|---|
| POSTGRES_USER / PASSWORD / DB | postgres | traceguard / dev only | change the password outside local dev |
| DATABASE_URL | api, gateway | local postgres | both processes share one database |
| API_KEY | api, gateway | dev_key_change_me | agent and dashboard credential |
| APPROVER_KEY | gateway | dev_approver_change_me | human approval decisions only |
| APPROVAL_ARGS_KEY | gateway | (required, no default) | 32 bytes hex sealing pending approval arguments; generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| APPROVAL_ARGS_KEY_PREVIOUS | gateway | (optional) | previous key kept during rotation until old rows expire |
| GATEWAY_PORT | gateway | 8091 | agent-facing listener |
| GATEWAY_CONTROL_PORT | gateway | 8093 | human approval control listener; agent credentials are rejected there |
| CONTROL_API_URL | gateway | http://127.0.0.1:8090 | API base the gateway forwards the fixed `/v1/ingest/events` telemetry path to; set to `http://api:8080` in compose |
| APPROVAL_TTL_SECONDS | gateway | 900 | pending approvals die after this (hard max 3600) |
| APPROVAL_CLAIM_LEASE_SECONDS | gateway | 30 | how long a consume attempt holds the CLAIMED lease before the sweep returns it to APPROVED |
| AUDIT_CHECKPOINT_PUBLIC_KEY | gateway | — | ed25519 PEM public key used only to verify operator-signed checkpoints; unset skips anchoring on verify |
| AUDIT_CHECKPOINT_KEY_FILE | operator CLI | — | path to the ed25519 private key; used by `pnpm audit:checkpoint` on the operator host, never mounted in a container |
| AUDIT_CHECKPOINT_PUBLIC_KEY_FILE | operator CLI | — | path to the public key for `audit:checkpoint prune` and `pnpm audit:verify` |
| APPROVAL_EXECUTION_TIMEOUT_SECONDS | gateway | 300 | how long an EXECUTING row may stay unresolved before the sweep finalizes it as OUTCOME_UNKNOWN |
| APPROVAL_MAX_PENDING_PER_CALLER | gateway | 10 | spec hard maximum; set lower only |
| APPROVAL_MAX_PENDING_PER_WORKSPACE | gateway | 100 | spec hard maximum; set lower only |
| APPROVAL_RATE_PER_MINUTE | gateway | 5 | new approval requests per caller per minute; spec hard maximum, set lower only |
| ALLOW_PRIVATE_UPSTREAMS | gateway | true | set false in production; true is for local mock upstreams |
| DASHBOARD_ORIGIN | api | http://localhost:5173 | the one origin allowed to fetch cross-origin |
| CAPTURE_RAW_ATTRIBUTES | api | false | store raw prompts/responses/tool args; recognized secrets are always redacted |
| DIAG_MAX_CALLS | api | 50 | advisory diagnostics: tool calls per run |
| DIAG_MAX_DURATION_MS | api | 1800000 | advisory diagnostics: run duration in ms |
| DIAG_MAX_TOKENS | api | 1000000 | advisory diagnostics: tokens per run |
| DIAG_REPEATED_FAILURES | api | 3 | advisory diagnostics: identical tool failures |
| UPSTREAM_TIMEOUT_MS | gateway | 60000 | ceiling on one upstream MCP exchange; aborts the request itself |
| GATEWAY_STATE_DIR | gateway | ./gateway-state | where the gateway records the highest signed policy version it accepted (§13.3); must persist across restarts |
| TOOL_PIN_META_ALLOWLIST | gateway | (empty) | comma-separated `_meta` keys covered by a tool's definition pin; empty pins no metadata |
| POLICY_SIGNING_KEY_FILE | policy-publisher | ./policy-keys/signing-key.pem | operator-side private key path; never present in the API or gateway containers |
| OAUTH_ISSUER | api + gateway | (empty) | OAuth 2.1 issuer used to validate access tokens (§7.3). Together with `OAUTH_AUDIENCE` and a JWKS source this switches both services from static keys to JWT validation |
| OAUTH_AUDIENCE | api + gateway | (empty) | the canonical audience/resource the tokens must name, e.g. `http://localhost:8091/mcp`; also the base of the RFC 9728 metadata URL |
| OAUTH_JWKS_FILE | api + gateway | (empty) | path to the issuer's JWKS document; use instead of the URL when the issuer is reachable only through a sidecar or mounted secret |
| OAUTH_JWKS_URL | api + gateway | (empty) | issuer JWKS URL; keys are refetched when a token names an unknown `kid`, at most once per 10 s |
| NODE_ENV | api + gateway | (unset) | `production` refuses to start without `OAUTH_ISSUER` + `OAUTH_AUDIENCE` + a JWKS source, and stops accepting the static `API_KEY`/`APPROVER_KEY` |
| DATABASE_URL_RETENTION | api | (unset) | connection string for the retention sweep, so approval pruning runs as `retention_job` (§13.4). Unset, the sweep uses `DATABASE_URL` |
| PORT | api | 8080 | container side; compose maps the host to 8090 |
| OTLP_MAX_BODY_BYTES | api | 1048576 | `/v1/traces` request body cap; larger bodies are rejected before parsing |
| OTLP_MAX_SPANS | api | 2000 | spans per request; spans past the cap are refused and reported in partial success |
| OTLP_MAX_ATTRIBUTES | api | 64 | stored attributes per span; extra keys are dropped |
| OTLP_MAX_ATTR_STRING | api | 4096 | stored attribute strings are truncated to this length |
| OTLP_SKEW_THRESHOLD_MS | api | 300000 | starts further ahead of receipt than this are stored with `clock_skew` |
| OTLP_LATE_WINDOW_MS | api | 86400000 | spans starting older than this are refused, never backfilled |
| OTLP_RATE_SPANS_PER_MINUTE | api | 60000 | per-caller span rate limit per minute; over it answers 429 |

Ports on a dev machine: API 8090, gateway 8091, approval control listener
8093, mock tools 8092 (internal network only), web 5173. Four networks keep
the boundary real: `front` (api, gateway, postgres, web), `tools` (gateway,
mock-tools; `internal: true`, so the upstream has no route off the host),
`agent_edge` (gateway, agent) and the agent's lack of everything else.
`pnpm test:security` asserts that from inside the agent container.

## Users and scoped keys

Single-user installs keep working: `API_KEY` has full access and
`APPROVER_KEY` approves. For teams, register the first user, which becomes
admin because no users exist yet, then create users and keys:

- `POST /v1/auth/register {email, password}` stays open only until the
  first user exists; afterwards it returns 403.
- `POST /v1/users {email, password, role}` needs an admin. Roles map to
  scopes: admin gets everything, member gets read, ingest, and gateway,
  approver gets read and approve.
- `POST /v1/users/:id/keys {name, scopes, expires_days}` returns the key
  plaintext exactly once; only its hash is stored.
- `POST /v1/auth/login {email, password}` mints a 24-hour bearer.
- `POST /v1/auth/logout` revokes the presented login bearer;
  `GET /v1/auth/me` returns the caller's kind, scopes, and workspaces.
- `DELETE /v1/users/:id/keys/:keyId` revokes.

Agent keys carry gateway scope at most, so they can ingest and call tools
but never approve. Writes default to admin unless the path is an explicit
agent or approver action. Passwords hash with scrypt, keys with SHA-256.

## Workspace membership

Keys write only inside the owner's workspaces. Admins and env keys keep
full access; everyone else belongs to workspaces through memberships:

- `POST /v1/workspaces {name}` creates one (admin).
- `GET /v1/workspaces` lists all for admins, only their own for members.
- `POST /v1/users/:id/memberships {workspace_id}` grants, the DELETE
  variant revokes (admin).
- `POST /v1/users/:id/keys` accepts an optional `workspace_id` pin. The pin
  must be one of the owner's memberships, otherwise creation fails loudly
  instead of minting a key that can write nowhere.

Ingest, OTLP, gateway calls, and budget reserve/settle/release all check
the target workspace and answer 403 `workspace_forbidden` outside it.
Member keys cannot auto-create workspaces by naming new ones; unknown names
are denied, not conjured.

Reads are scoped the same way. Run lists, run detail, traces, usage,
servers, policies, approvals, decisions, budgets, and eval runs show only the
caller's workspaces; foreign ids read as 404 so they cannot be probed.
Registry reads (servers, policies) need only read scope, while every write
to them stays admin. Eval suites and cases are shared templates with no
workspace. Audit, deliveries, retention history, and actuals import stay
admin-only.
