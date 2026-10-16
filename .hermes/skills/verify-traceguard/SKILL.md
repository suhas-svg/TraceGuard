---
name: verify-traceguard
description: "Drive the TraceGuard web dashboard (apps/web) like a user against the local docker-compose stack. Use to prove UI behavior — runs list, trace explorer, approvals, policies, costs — with captured evidence."
version: 0.1.0
author: Suhasan Kanagala (suhas-svg), Hermes Agent
license: MIT
platforms: [windows]
metadata:
  hermes:
    tags: [verification, testing, feature-map, proof, harness]
    related_skills: [browser-ui-walkthrough, create-verification-skill, maintain-verification-skill]
---

# Verify TraceGuard

Scripted verification of the TraceGuard web dashboard (`E:\Desktop\Traceguard\apps\web`)
against the local full stack (postgres + api + gateway). Drives the real UI through
`browser_exec`; never pokes React state or test-only endpoints.

Repo-local skills need the project trusted once: `hermes skills trust` in the repo root.

## Launch

Everything runs from the repo root (`E:\Desktop\Traceguard`, Windows, Git Bash shell —
POSIX syntax works in `terminal`; use `C:/...` paths for native tools).

1. **Docker stack** (postgres :5432, api :8090, gateway :8091):

   ```sh
   docker compose up -d --build postgres api gateway
   ```

   If `docker info` fails, start Docker Desktop first:
   `powershell -Command "Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'"`,
   then poll `docker info` until it answers (~10-60 s). The image build takes a few
   minutes on first run.

2. **Migrations** — the API does NOT auto-migrate. Apply every file in
   `apps/api/migrations/*.sql` in filename order through the postgres container:

   ```sh
   for f in apps/api/migrations/0*.sql; do
     echo "== $f"; docker compose exec -T postgres psql -U traceguard -d traceguard -v ON_ERROR_STOP=1 < "$f";
   done
   ```

   Re-running is safe where the SQL is idempotent; ON_ERROR_STOP surfaces real breaks.

3. **Web dashboard** (vite dev server, :5173):

   ```sh
   cd apps/web && npm run dev
   ```

   Run in `terminal` with `background=true`; note the returned `session_id` — it is the
   teardown handle. Ready when `curl -s -o /dev/null -w "%{http_code}" http://localhost:5173/`
   prints `200`.

4. **Seed data** (optional but required for runs/trace/cost evidence):

   ```sh
   npm run start -w demo-agent-ts        # one run with a model event
   ```

   Run it several times for a populated list. Env knobs: `TRACEGUARD_URL`
   (default `http://localhost:8090`), `TRACEGUARD_API_KEY` (default `dev_key_change_me`).

Teardown: see **Cleanup**.

## Doctor

One read-only gate — run this whenever anything looks off:

```sh
curl -s -o /dev/null -w "api:%{http_code} " http://localhost:8090/healthz; \
curl -s -o /dev/null -w "ready:%{http_code} " http://localhost:8090/readyz; \
curl -s -o /dev/null -w "gw:%{http_code} " http://localhost:8091/healthz; \
curl -s -o /dev/null -w "web:%{http_code}\n" http://localhost:5173/
```

Expected: `api:200 ready:200 gw:200 web:200`. `ready` non-200 means postgres is down or
migrations were not applied. A 401 anywhere means the wrong key is configured — the
dashboard defaults (`dev_key_change_me`, `dev_approver_change_me`) match the compose
defaults, so only localStorage overrides break this.

**Edit/delete actions failing with `Failed to fetch` while reads work** is a CORS preflight
problem, not an auth one: the browser blocks PUT/DELETE unless the response carries an
explicit method list. Probe it directly:

```sh
curl -s -i -X OPTIONS http://localhost:8091/v1/policies/x \
  -H "Origin: http://localhost:5173" -H "Access-Control-Request-Method: PUT" | grep -i allow-methods
```

An empty result means every PUT/DELETE in the dashboard (policy edit, webhook delete, key
revoke, retention delete) is dead while POST creates still work — POST is a CORS-safelisted
method and never trips the check.

## Drive

Harness: `browser_exec` (the Python helper: `new_tab(url)`, `goto_url(url)`,
`page_info()`, `js(expr)`, `fill_input(selector, text)`, `click_at_xy(x, y)` via
`cdp('DOM.getBoxModel', backendNodeId=...)`, `capture_screenshot()`). One named session
(`session="traceguard"`) across a run; text-first — read state with `js()`, not screens.

Stable handles (from `apps/web/src/`):

| Target | Handle |
|---|---|
| Nav | `aside nav[aria-label="Primary"]` → buttons, active one has `aria-current="page"` |
| Run rows | table rows in `#/runs`; open via the `font-mono` button in col 1 |
| Status filter | `[role="group"][aria-label="Filter by status"]` buttons (aria-pressed) |
| Span rows | buttons inside the left trace card; selected gets `bg-brand-50` |
| Connection drawer | `[role="dialog"][aria-label="Connection settings"]`; toggle button is the status dot at the sidebar bottom |
| Theme toggle | button `aria-label` "Switch to light/dark mode" |
| Loading skeletons | `[role="status"][aria-label="Loading runs..."]` / `"Loading trace..."` / `"Loading approvals..."` / `"Loading rules..."` |
| Runs KPI tiles | `button[aria-pressed]` whose text starts with `Failed` or `Running` (toggle filter) |
| Runs search | `input[aria-label="Search runs"]` |
| Sortable headers | `thead th[aria-sort]`; the inner `button` toggles asc/desc |
| Command palette | `[role="dialog"][aria-label="Command palette"]`; Ctrl/Cmd+K toggles it, input `aria-label="Command palette search"`, entries `[role="option"]` |
| Approval cards | the smallest `div` containing the tool name AND an `Approve` button (the name's own header div has none); a decided card leaves the current filter by design |
| Users controls | per-card `select[aria-label="Workspace"]` (grants on change) and `button[aria-label="Remove from <workspace>"]`; `input[aria-label="New workspace name"]`; `input[type=email]`/`input[type=password]` for the user form |
| Evaluations | `input[name="runId"]` (open one eval run) and `input[placeholder="run-id-1, run-id-2"]` (compare) — both real forms, submit with `requestSubmit()` |

Routing is hash-based (`src/router.ts`): `#/runs`, `#/runs/<runId>`, `#/evals`,
`#/policy`, `#/approvals`, `#/webhooks`, `#/retention`, `#/costs`, `#/users`.
Deep links and browser back/forward are part of the contract — always test navigation
through the URL, not just clicks.

Core recipe (open a run and come back):

```python
new_tab("http://localhost:5173/#/runs")
wait_for_load()
run_id = js("document.querySelector('tbody .font-mono')?.textContent")   # short id
js("document.querySelector('tbody .font-mono').click()")
wait_for_load()
print(js("location.hash"))          # expect #/runs/<full-id>
js("history.back()")
wait_for_load()
print(js("location.hash"))          # expect #/runs again
```

Two harness traps, both hit in real runs:

- **Real-profile lock.** If `browser_exec` fails with "chrome is running and has its
  profile locked", the harness wants to copy the real Chrome profile. Do NOT quit the
  user's browser. Workaround: `hermes config set browser.use_real_profile false`, run
  the drive, then tell the user the flag is off (restore with `... true`).
- **Hidden tabs don't poll.** A headless/backgrounded tab reports
  `document.visibilityState === "hidden"` and React Query pauses `refetchInterval`
  there. Before asserting polling, run `cdp("Page.bringToFront")` and confirm
  `js("document.visibilityState")` is `visible`; otherwise a "no polling" conclusion is
  wrong.

Before trusting any screen: `js("window.__tgErrors ?? []")` plus a console sweep via
`cdp("Runtime.enable")` listeners is the ideal; the cheap version is checking
`page_info()` text for error banners (`role="alert"`).

## Evidence

Proof artifacts go to `.hermes/skills/verify-traceguard/evidence/<YYYY-MM-DD-HHMM>/`
(create the dir; it survives cleanup — never delete it in Cleanup):

- `capture_screenshot()` for each key state (runs list, trace view, drawer open).
- `js()` extractions of the asserting value (e.g. `location.hash`, row counts) written
  to `evidence/<ts>/checks.txt` — the check output IS the proof, screenshots support it.
- Record the command and the observed value side by side: `check: <what> => <value>`.

Proof standards: exercise the real user path (clicks, URLs, forms); capture the action
and the resulting state; verify side effects (a seeded run appearing in the list, a
decision changing an approval's status) not just the final screen; read-only features
are proven by their rendering of real API data, not by stubbing.

## Cleanup

Kill only what this run started, by handle:

- web dev server: kill the background `terminal` session id recorded at Launch
  (`process_manage` kill, or `taskkill` on that PID — never `pkill node`/`taskkill /IM`).
- docker: `docker compose down` (add `-v` only when the run created throwaway data the
  user does not want; the default keeps `pgdata`).
- Never delete `evidence/`.

## Helpers

None shipped — `browser_exec` inline recipes are the harness. Seed runs come from the
repo's own `demo-agent-ts` (`npm run start -w demo-agent-ts`), which is also the
smoke test for ingestion.
