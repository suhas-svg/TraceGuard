# Webhooks

The webhooks screen manages HMAC-signed event subscriptions and shows the delivery log with a
retry per failed delivery. Secrets are write-only: reads never return the stored value.

## Sub-features

- `webhooks-create` adds a subscription (name, URL, one or more event types, optional HMAC secret).
- `webhooks-list` lists subscriptions with their event types and a `Delete` action.
- `webhooks-deliveries` lists delivery attempts (subscription, event, status, tries, last error).
- `webhooks-retry` re-sends a `failed` delivery and increments its try count.

## How to get to it (user POV)

- Click `Webhooks` in the sidebar (`#/webhooks`).
- `Add subscription` opens the form; each subscription row ends in `Delete`; each failed
  delivery row ends in `Retry`.

## Driving it with browser_exec

Preconditions:

- Baseline met (`features/README.md`). Deliveries only exist after an event was emitted; a
  stale dev database usually has failed ones pointing at dead receivers — that is fine.

- **Create.** Open the form (`js("[...document.querySelectorAll('main button')].find(b=>b.textContent.trim()==='Add subscription').click()")`),
  fill `input[aria-label="Webhook name"]` and `input[aria-label="Webhook URL"]`, tick an event
  chip, then submit with `js("document.querySelector('main form button[type=submit]').click()")`.
  The name appears as `span.font-medium` in the `Subscriptions` card.
- **Delete.** Click the `Delete` in that row — the same smallest-divider pattern as other
  card lists: the div whose text contains the name and whose buttons include `Delete`.
  The name disappears and no `[role="alert"]` appears.
- **Retry.** `js("document.querySelectorAll('tbody tr')[0]?.querySelector('button')?.click()")`
  on a failed delivery; its `Tries` cell increments (a dead receiver fails again — the
  increment is the proof, not a success status).
- **Proof.** Record the subscription name and the delivery's before/after `Tries` in
  `checks.txt`; screenshot the deliveries table.

## Gotchas

- Two buttons read `Add subscription` (the header toggle and the form's submit). Submit through
  `main form button[type=submit]` so the click cannot toggle the form shut instead.
- The subscription list is a card list, not a table; the only `<table>` on the screen is the
  delivery log, so count rows with that in mind.
- `Retry` only renders while a delivery's status is `failed`; a successful delivery has no button.
- Deleting a subscription does not delete its delivery history; old rows stay in the log.
