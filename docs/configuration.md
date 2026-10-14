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
- `DELETE /v1/users/:id/keys/:keyId` revokes.

Agent keys carry gateway scope at most, so they can ingest and call tools
but never approve. Writes default to admin unless the path is an explicit
agent or approver action. Passwords hash with scrypt, keys with SHA-256.
