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
| GATEWAY_PORT | gateway | 8091 | |
| APPROVAL_TTL_SECONDS | gateway | 300 | pending approvals die after this |
| ALLOW_PRIVATE_UPSTREAMS | gateway | true | set false in production; true is for local mock upstreams |
| DASHBOARD_ORIGIN | api | http://localhost:5173 | the one origin allowed to fetch cross-origin |
| PORT | api | 8080 | container side; compose maps the host to 8090 |

Ports on a dev machine: API 8090, gateway 8091, mock tools 8092
(internal network only), web 5173.
