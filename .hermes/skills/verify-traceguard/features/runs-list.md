# Runs list

The runs list is the dashboard home: every agent execution, newest first, with status
filtering, cursor pagination, automatic refresh, and one click into a run's trace.

## Sub-features

- `runs-load` renders seeded runs with agent, status, start time, spans, and tokens in/out.
- `runs-filter` narrows the list by status via the segmented control.
- `runs-paginate` appends older pages with `Load more` while `next_cursor` exists.
- `runs-poll` refreshes the visible list in place every ~10 s without user action.
- `runs-open` opens a run's trace view via its short-id button.
- `runs-kpi` overview tiles read global totals from `/v1/runs/counts`; `Failed` and
  `Running` are toggle buttons (`aria-pressed`) that filter the list.
- `runs-search` filters the loaded pages by run-id prefix or agent name via the
  `Search runs` input; the caption switches to `Showing N of M loaded`.
- `runs-sort` sorts the loaded pages by Started / Spans / Tokens through the clickable
  headers (`aria-sort`); the untouched order stays newest-first from the server.

## How to get to it (user POV)

- Land on `http://localhost:5173/#/runs` (the default route).
- Click `Runs` in the left sidebar nav.
- Click a run's short id in the first table column.

## Driving it with browser_exec

Preconditions:

- Baseline met (`features/README.md`), ≥2 seeded runs, session `traceguard` on `#/runs`.
- **Load.** Open the list. Run `new_tab("http://localhost:5173/#/runs")`, `wait_for_load()`.
  `js("document.querySelectorAll('tbody tr').length")` is ≥2, each row shows a status badge,
  `Started` reads relative (`4m ago`, absolute time in the cell `title`), and a
  `N runs loaded` caption sits under the table.
- **Filter.** Press `Failed`. Run
  `js("[...document.querySelectorAll('[aria-label=\"Filter by status\"] button')].find(b=>b.textContent==='Failed').click()")`.
  `js("location.hash")` stays `#/runs`; every rendered row's status cell reads `failed`
  (or the empty state shows when none exist).
- **KPI filter.** Press the `Failed` tile —
  `js("[...document.querySelectorAll('button[aria-pressed]')].find(b=>b.textContent.startsWith('Failed')).click()")`.
  That tile gains `aria-pressed="true"`, the segmented control moves to `Failed`, and pressing
  the tile again clears the filter back to `All`.
- **KPI totals are global.** While a filter is active the tiles still read unfiltered
  totals: read `js("[...document.querySelectorAll('button[aria-pressed]')].filter(b=>/^(Failed|Running)\\s*\\d/.test(b.textContent)).map(b=>b.textContent.replace(/\\s+/g,' '))")`
  before and after filtering — the numbers match.
- **Search.** `fill_input('input[aria-label="Search runs"]', 'ts-agent')`; the row count
  drops to the matches and the caption reads `Showing N of M loaded`. Clearing the input
  restores every loaded row.
- **Sort.** Click a sortable header, e.g.
  `js("[...document.querySelectorAll('thead th button')].find(b=>b.textContent.includes('Spans')).click()")`.
  That `th` reports `aria-sort="descending"` and the first row holds the largest span count;
  clicking again flips to `ascending`.
- **Reset filter.** Press `All` the same way; row count returns to ≥2.
- **Paginate.** With >50 seeded runs, click `Load more`
  (`js("[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Load more').click()")`).
  Row count increases and `Load more` disappears when `next_cursor` is exhausted.
- **Poll.** Wait 12 s without interacting. `js("performance.getEntriesByType('resource').filter(e=>e.name.includes('/v1/runs')).length")`
  is ≥2 (initial load plus the interval refetch).
- **Open.** Click the first row's short-id button
  (`js("document.querySelector('tbody .font-mono').click()")`). `js("location.hash")`
  matches `#/runs/<full-run-id>` and a span tree renders.
- **Proof.** Screenshot the list, write the row count and hash to `checks.txt`.

## Gotchas

- The skeleton (`role="status"` `aria-label="Loading runs..."`) flashes only on first
  load per filter — assert on the table, not on catching the skeleton.
- Short ids are 8 chars (`id.slice(0, 8)`); the hash holds the full id.
- `Load more` is disabled while a page fetch is in flight; don't assert too fast.
- Polling refetches loaded pages; row order can shift as new runs arrive — assert by
  content, not by index, when the demo agent runs concurrently.
