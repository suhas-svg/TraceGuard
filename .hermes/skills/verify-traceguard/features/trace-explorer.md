# Trace explorer

Opening a run shows its execution tree: nested spans with per-span timing bars, and a
detail panel with tokens, cost, provider/model, and error or denial cause.

## Sub-features

- `trace-tree` renders parent/child spans in time order with duration bars.
- `trace-detail` shows the selected span's fields and raw attributes JSON.
- `trace-deeplink` loads a specific run straight from `#/runs/<runId>`.
- `trace-back` returns to the list via both the `Back to runs` button and browser back.
- `trace-cost` shows the run's estimated cost (`est. $x.xxxx`, ` (partial)` when usage is incomplete).
- `trace-keyboard` — with a span button focused, `ArrowUp` / `ArrowDown` walk the flattened
  tree, selecting and focusing the previous/next span.

## How to get to it (user POV)

- Click a run's short id on the runs list.
- Paste/open `http://localhost:5173/#/runs/<runId>` directly.
- Press the browser back button, or the page's `Back to runs` button.

## Driving it with browser_exec

Preconditions:

- Baseline met; at least one run with spans (run `demo-agent-ts` again if the trace shows `No spans recorded.`).
- **Open from list.** From `#/runs`, click the first row's short-id button.
  `js("location.hash")` starts with `#/runs/` and the left card lists span buttons.
- **Select a span.** Run `js("document.querySelectorAll('button')[...]")` — simplest:
  `js("document.querySelector('.space-y-0\\\\.5 button, [class*=space-y] button').click()")` or pick by text via
  `[...document.querySelectorAll('button')].find(b=>b.textContent.includes('model.request'))`.
  The right card shows `span <id>` with rows for Operation, Status, Tokens, Duration.
- **Arrow keys.** Focus the first span button (`js("document.querySelector('[data-span]').focus()")`),
  then dispatch `js("document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}))")`.
  `js("document.activeElement.dataset.span")` is now the next span in DOM order and the detail
  panel follows it; `ArrowUp` walks back.
- **Deep link.** `goto_url("http://localhost:5173/#/runs/" + fullId)` (full id from
  `js("location.hash.split('/')[2]")`). The same trace renders without clicking through the list.
- **Back button.** `js("history.back()")` then `wait_for_load()`; `js("location.hash")` is
  `#/runs` and the runs table renders.
- **Back to runs button.** Re-open a run, click `Back to runs`
  (`js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Back to runs').click()")`);
  hash is `#/runs`.
- **Cost.** Read `js("document.body.innerText")` for `est. $`; record the value in `checks.txt`.
- **Proof.** Screenshot the trace with a span selected; record hash + detail rows.

## Gotchas

- Span bars are `aria-hidden` decorative; assert on span button text (operation_type, ms), not bar widths.
- Unknown run ids render an error alert with `Back to runs` — that is the expected
  behavior for `trace-error`, not a broken page.
- The right panel shows `Select a span...` empty state until a span is clicked.
- Denial cause text reads `denied by <reason>`; don't assert the literal word `denied` alone.
