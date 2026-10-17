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
| GATEWAY_PORT | gateway | 8091 | |
| APPROVAL_TTL_SECONDS | gateway | 300 | pending approvals die after this |
| ALLOW_PRIVATE_UPSTREAMS | gateway | true | set false in production; true is for local mock upstreams |
| DASHBOARD_ORIGIN | api | http://localhost:5173 | the one origin allowed to fetch cross-origin |
| CAPTURE_RAW_ATTRIBUTES | api | false | store raw prompts/responses/tool args; recognized secrets are always redacted |
| DIAG_MAX_CALLS | api | 50 | advisory diagnostics: tool calls per run |
| DIAG_MAX_DURATION_MS | api | 1800000 | advisory diagnostics: run duration in ms |
| DIAG_MAX_TOKENS | api | 1000000 | advisory diagnostics: tokens per run |
| DIAG_REPEATED_FAILURES | api | 3 | advisory diagnostics: identical tool failures |
| UPSTREAM_TIMEOUT_MS | gateway | 60000 | ceiling on one upstream MCP exchange; aborts the request itself |
| PORT | api | 8080 | container side; compose maps the host to 8090 |

Ports on a dev machine: API 8090, gateway 8091, mock tools 8092
(internal network only), web 5173.

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
