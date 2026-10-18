# Policy center

The policy center lists registered upstream MCP servers, the versioned tool rules
(allow / deny / require approval) the gateway enforces, and the **active signed policy
version**. Rules are drafts: enforcement reads only the signed bundle an operator
publishes with `tools/policy-publisher`, so a freshly created rule does not gate a call
until a publish activates it (and before the first publish, calls fail closed with
`503 policy_unavailable`).

## Sub-features

- `policy-servers` lists upstream servers with a `Rediscover` action.
- `policy-rules` lists rules with effect badge, tool scope, priority, and version.
- `policy-create` creates a rule through the form (validates conditions JSON).
- `policy-edit` opens an existing rule and saves it as version n+1 (never in place).
- `policy-signed` shows the active signed version (hash, publisher, time) and up to five
  previous versions; empty state says nothing is published yet.
- `policy-verify-chain` (in Audit history) calls `POST /v1/audit/verify` and renders the
  verdict: `chain verified` or `tampering detected` with the first problem.

## How to get to it (user POV)

- Click `Policy` in the sidebar (`#/policy`).
- Click `New rule` in the page header; click `Edit` on a rule row; click `Verify chain`
  next to `Audit history`.

## Driving it with browser_exec

Preconditions:

- Baseline met; gateway up (:8091) with the dashboard's API key (`dev_key_change_me`).
- A signed policy has been published at least once, otherwise every gateway interaction
  reports `policy unavailable`:
  `npm run policy:keygen` (once), `npm run policy:trust -- --workspace default` (once),
  `npm run policy:publish -- --workspace default` (repeat after rule changes).
- **Load.** Open `#/policy`. Servers card lists registered servers (or the honest
  `No servers registered.` line); rules table lists rules or the empty state; the
  `Signed policy` section shows the active version, or the empty state naming
  `policy-publisher`.
- **Create.** Click `New rule` (`js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='New rule').click()")`).
  Fill with `fill_input('input[aria-label="Rule name"]', "verify-harness-rule")`,
  select effect via `fill_input('select[aria-label="Effect"]', "deny")` is not valid for
  selects — use `js("const s=document.querySelector('select[aria-label=\"Effect\"]'); s.value='deny'; s.dispatchEvent(new Event('change',{bubbles:true}))")`,
  tool `fill_input('input[aria-label="Tool name"]', "shell_exec")`, conditions left `{}`.
  Click `Create rule`. The form closes and a row `verify-harness-rule` with badge `deny`
  and `v1` appears. Assert it is a draft: the `Signed policy` section's active version
  does not change until a publish runs.
- **Edit.** Click `Edit` on that row; the form reopens prefilled with button text
  `Save as v2`. Click it; the row now reads `v2` and the old id is superseded (list shows
  the newest version).
- **Publish round-trip.** `npm run policy:publish -- --workspace default`, then reload
  `#/policy`: the active version increments and its hash changes.
- **Verify chain.** Click `Verify chain`; expect the `chain verified` badge and a checked
  count. (Downgrade only by tampering with the database, which is outside this harness.)
- **Second view.** `goto_url` to `#/policy` fresh (or `Refresh`-less refetch via reload);
  the rule persists.
- **Proof.** Screenshots of the table before/after edit plus the signed-policy section;
  `checks.txt` records rule name, effect, both version numbers, and the active signed
  version before/after publish.

## Gotchas

- The dashboard is read-mostly for policy writes: it uses the gateway's policy API with
  the configured key; a 403 means the key lacks scope, not a UI failure.
- `Save as vN` is a PUT: if it fails with `Failed to fetch` while `Create rule` works,
  the gateway is missing `Access-Control-Allow-Methods` (see `../SKILL.md` → Doctor).
- Invalid conditions JSON shows `conditions must be valid JSON` inline and does NOT
  create a rule — assert the alert and the absent row.
- Edits create a new version; `policies` list shows one row per rule (newest version),
  don't count versions as separate rules.
- A rule is inert until published. If a tool call returns `503 policy_unavailable` or
  `403 ... not in the active signed policy`, the fix is a publish, not a rule edit.
- Rule deletion is not exposed in the UI; leave `verify-harness-rule` behind or clean it
  via API and note it in evidence.
