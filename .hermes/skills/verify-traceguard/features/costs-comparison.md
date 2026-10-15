# Costs comparison

The costs screen compares TraceGuard's estimated spend against provider actuals over a
time window: paired bars per provider/model plus token counts and variance.

## Sub-features

- `costs-window` runs a comparison for the chosen provider and day window.
- `costs-bars` renders estimated (indigo) vs billed (green) paired bars.
- `costs-variance` shows `$x.xxxx (y.y%)` variance or `n/a` when no actuals exist.
- `costs-empty` shows honest empty states for no-window and no-usage cases.

## How to get to it (user POV)

- Click `Costs` in the sidebar (`#/costs`).
- Set `Provider (blank = all)` and `Past days`, then click `Compare`.

## Driving it with browser_exec

Preconditions:

- Baseline met; at least one seeded run with model usage (cost estimates come from
  run usage × pricing; missing pricing marks rows `partial`).
- Optional: imported actuals via `POST /v1/reconciliation/actuals` — without them the
  `Billed` column reads `no actuals` and variance `n/a`, which is a valid state to prove.
- **Load.** Open `#/costs`. The form card renders; below it the `Pick a window and
  compare.` empty state.
- **Compare.** Set days: `fill_input('input.w-24', '30')` (or the `Past days` field by
  label order), click `Compare` (`js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Compare').click()")`).
  A table appears with columns Model, Tokens in/out, Split, Estimated, Billed, Variance.
- **Bars + values.** For the first row read `js("document.body.innerText")`; the row
  shows `provider/model`, `formatMicro` dollar values, and either variance numbers or
  `no actuals` / `n/a`.
- **Empty window.** Set `Past days` to `0`-adjacent junk like `1` with a provider that
  has no usage (e.g. `nope`); the `No usage in this window.` empty state renders.
- **Proof.** Screenshot the table; `checks.txt` records window params and first-row
  values.

## Gotchas

- `Past days` is free text; invalid values fall back to 30 — don't assert the input
  value, assert the result.
- Rows with `missing_pricing` show a `partial` badge and incomplete estimates; the run's
  usage endpoint marks the same data `cost_partial`.
- Bars are decorative (`Split` column); assert the text values, not widths.
- Comparison is estimate-vs-actuals reconciliation, not billing truth — evidence should
  quote the values as estimates.
