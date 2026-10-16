# Users

Users owns the team surface: accounts, API keys with scopes, and workspace membership. A minted
key's plaintext is shown once, at mint; reads never return it.

## Sub-features

- `users-create` creates a user (email, 12+ character password, role member/approver/admin).
- `users-keys-mint` mints a scoped key (name, scopes, optional workspace pin) and shows the plaintext once.
- `users-keys-revoke` revokes a key.
- `users-workspaces` creates workspaces and grants or revokes membership.

## How to get to it (user POV)

- Click `Users` in the sidebar (`#/users`).
- `New user` and `New workspace` forms sit at the top; every user card carries `Mint key` and
  `Revoke` buttons.

## Driving it with browser_exec

Preconditions:

- The dashboard key must carry admin scope; the compose default (`dev_key_change_me`) does.
- The dev database can hold hundreds of users — target the first card that contains `@` and
  never assume page-wide counts beyond a before/after delta.

- **Mint.** Click `Mint key` on a user card, fill the `Key name` input, leave the default
  `read` scope checked, then submit with `js("[...document.querySelectorAll('main form')].find(f=>f.innerText.includes('Key name')).requestSubmit()")`.
  The plaintext key appears once (`/^tg_[A-Za-z0-9_-]{20,}$/`) and a new key row joins the card.
- **Prove the plaintext without leaking it.** Assert presence and length only; never copy the
  value into `checks.txt`, screenshots, or the transcript.
- **Revoke.** Click that key row's `Revoke` — the row disappears and the card's `Revoke` count
  returns to its pre-mint value.
- **Proof.** `checks.txt` records the two counts and a boolean for the plaintext element.

## Gotchas

- Scope chips are checkboxes inside labels, and `read` is checked by default: clicking it while
  "filling the form" unchecks it, and an empty scope list fails the API with `invalid_key`.
- The mint payload is `{name, scopes}`; `expires_days` defaults to 90 and `workspace_id` is only
  sent when a workspace is pinned.
- Target a key row as the smallest `div` whose text contains the key name and whose buttons
  include `Revoke` — the name span's own closest div has no buttons.
- A minted key is shown once: after a reload it is unrecoverable, which is the intended design,
  not a bug to file.
