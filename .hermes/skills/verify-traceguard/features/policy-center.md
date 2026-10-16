# Policy center

The policy center lists registered upstream MCP servers and the versioned tool rules
(allow / deny / require approval) the gateway enforces before any protected call.

## Sub-features

- `policy-servers` lists upstream servers with a `Rediscover` action.
- `policy-rules` lists rules with effect badge, tool scope, priority, and version.
- `policy-create` creates a rule through the form (validates conditions JSON).
- `policy-edit` opens an existing rule and saves it as version n+1 (never in place).

## How to get to it (user POV)

- Click `Policy` in the sidebar (`#/policy`).
- Click `New rule` in the page header; click `Edit` on a rule row.

## Driving it with browser_exec

Preconditions:

- Baseline met; gateway up (:8091) with the dashboard's API key (`dev_key_change_me`).
- **Load.** Open `#/policy`. Servers card lists registered servers (or the honest
  `No servers registered.` line); rules table lists rules or the empty state.
- **Create.** Click `New rule` (`js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='New rule').click()")`).
  Fill with `fill_input('input[aria-label="Rule name"]', "verify-harness-rule")`,
  select effect via `fill_input('select[aria-label="Effect"]', "deny")` is not valid for
  selects — use `js("const s=document.querySelector('select[aria-label=\"Effect\"]'); s.value='deny'; s.dispatchEvent(new Event('change',{bubbles:true}))")`,
  tool `fill_input('input[aria-label="Tool name"]', "shell_exec")`, conditions left `{}`.
  Click `Create rule`. The form closes and a row `verify-harness-rule` with badge `deny`
  and `v1` appears.
- **Edit.** Click `Edit` on that row; the form reopens prefilled with button text
  `Save as v2`. Click it; the row now reads `v2` and the old id is superseded (list shows
  the newest version).
- **Second view.** `goto_url` to `#/policy` fresh (or `Refresh`-less refetch via reload);
  the rule persists.
- **Proof.** Screenshots of the table before/after edit; `checks.txt` records rule name,
  effect, and both version numbers.

## Gotchas

- The dashboard is read-mostly for policy writes: it uses the gateway's policy API with
  the configured key; a 403 means the key lacks scope, not a UI failure.
- `Save as vN` is a PUT: if it fails with `Failed to fetch` while `Create rule` works,
  the gateway is missing `Access-Control-Allow-Methods` (see `../SKILL.md` → Doctor).
- Invalid conditions JSON shows `conditions must be valid JSON` inline and does NOT
  create a rule — assert the alert and the absent row.
- Edits create a new version; `policies` list shows one row per rule (newest version),
  don't count versions as separate rules.
- Rule deletion is not exposed in the UI; leave `verify-harness-rule` behind or clean it
  via API and note it in evidence.
