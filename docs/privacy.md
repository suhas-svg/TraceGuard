# Privacy

What the platform stores, what it refuses to store by default, how long
data lives, and how it is deleted. The short version: structural
execution data is stored, content is not, and the one v1 exception —
pending approval arguments — is encrypted, time-limited, and visible only
to the approver who must decide it.

## Captured by default

| Data | Where | Notes |
|---|---|---|
| Run metadata (ids, status, timings, agent attribution) | `runs` | attribution fields are caller-supplied; see "Limits" in `docs/security.md` |
| Span structure (ids, parent id, name, kind, status, timings, clock skew) | `spans` | no prompt, completion, or tool payload content |
| Model / provider identifiers, token counts where reported | `spans`, `model_usage` | separate nullable input/output/cached fields; unknown stays `NULL` |
| Priced usage and cost estimates | `spans`, budget ledgers | integer micro-USD; unknown price or usage is `NULL`, never zero |
| Gateway decisions (policy version, matched rule ids, argument hash) | `policy_decisions` | arguments themselves are never stored here |
| Audit events (actor, action, resource, sanitized metadata) | `audit_events` | hash-chained; never contains arguments, results, or secrets |
| API key and password hashes | `api_keys`, `users` | SHA-256 / scrypt hashes only; key plaintext is shown once at creation |

## Not captured by default

- **Raw prompt and completion content.** Known content keys in span
  attributes are replaced with `[NOT CAPTURED]` before persistence.
- **Raw tool arguments and outputs in traces.** Same replacement, same
  boundary: redaction runs before the write, not in the UI.
- Setting `CAPTURE_RAW_ATTRIBUTES=true` opts in to raw attribute capture
  for the span/event path; the API logs a startup warning while it is on.
  Secret patterns are still redacted first.

## Always redacted

Recognized secret patterns are stripped before persistence even when
capture is enabled: PEM private keys, `sk-…` / `sk-ant-…` API keys, GitHub
`gh[pousr]_` tokens, AWS key ids (`AKIA…`), Slack `xox…` tokens, JWTs, and
`Bearer` tokens. The same pass runs at event ingest, OTLP ingestion,
evaluation replay, and gateway-denial span writes.

## The one v1 exception: pending approval arguments

An approval cannot be decided without showing the approver the exact
arguments. This is the only place tool arguments are stored.

- Arguments are sealed with AES-256-GCM (`AES_KEY`; the key material is
  supplied by the operator and is not derived from the database).
- TTL defaults to 15 minutes, hard maximum 60 minutes. Expiry is enforced
  on server/database time.
- Only principals with the `approve` scope can read them, over TLS, with
  `Cache-Control: no-store`. Reads are not cached by the browser or any
  intermediary.
- The ciphertext is wiped on rejection, expiry, cancellation, policy
  invalidation, quarantine, and every terminal execution outcome. What
  remains afterwards is the redacted summary and the canonical argument
  hash that binds the approval.
- If the ciphertext is missing, expired, or fails authentication, the call
  does not execute.
- Arguments never appear in normal logs, telemetry, audit payloads, or
  trace spans.

## Credentials

- Upstream MCP credentials live in the gateway's configured secret source
  and are injected by the gateway; inbound agent tokens are never forwarded
  upstream.
- Inbound agent authentication is OAuth (or a development-only static key
  that refuses to run in a production configuration).
- Ingestion keys are project-scoped, stored as hashes, displayable once,
  expirable, and revocable.
- Audit checkpoint signing keys and policy signing keys live on the
  operator's host, never in the database or a service container.

## Retention

| Data | Default retention | Mechanism |
|---|---|---|
| Spans / runs | 7 days or 100,000 spans, whichever limit is reached first (configurable) | `POST /v1/retention/run`, called from cron; deletes whole traces where possible |
| Terminal approvals | per retention rule (age) | same; pending approvals are never a deletion target |
| Webhook deliveries | per retention rule (age) | same |
| Audit events | indefinite | never pruned by the normal retention job |
| Pending approval arguments | the approval TTL (≤ 60 min) | ciphertext wiped at the state transition, independent of retention rules |
| Policy versions, tool pins, decisions, budgets | indefinite | not valid retention targets; the API refuses them |

Retention never deletes gateway security decisions or audit events under
the trace-retention policy. Removal runs report per-rule deletion counts
and write an audit row for each run.

## Deletion

- **Trace data:** governed by retention rules above. Deleting a run
  cascades its spans; correlation ids on surviving records (decisions,
  audit) remain as hashes/ids, not content.
- **Approval arguments:** deleted at the terminal transition as described
  above, not later.
- **An individual's data:** deployment-local: remove the user's API keys
  and memberships, delete or age out their runs via retention, and note
  that audit events are append-only by design (they keep actor ids and
  action metadata, never payload content).
- **Full reset:** `docs/operations.md` covers backups, restores, and how to
  rebuild a workspace from a clean database.

## Untrusted by construction

Incoming OTLP attributes, resource fields, tool descriptions, and tool
results are untrusted data. They are bounded, sanitized, and stored as
data; they are never treated as authorization inputs. Security and
approval decisions use server/database time and authenticated identities,
never self-reported metadata such as MCP `clientInfo` or span attributes.
