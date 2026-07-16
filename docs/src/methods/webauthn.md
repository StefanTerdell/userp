# Passkeys (WebAuthn)

`WebauthnConfig::new(rp_origin, rp_name)` — the RP id defaults to the
origin's domain. Two ceremonies are wired end to end (JSON endpoints + inline
page scripts):

- **Registration**: a logged-in user adds a passkey from the account page.
  Resident (discoverable) keys are required so the login below works.
- **Login**: usernameless — "Sign in with a passkey" on the login page runs a
  discoverable ceremony; authery resolves the credential (and user) by
  credential id, so your generic user-id type is never embedded in
  authenticator hardware.

Credentials are stored through your store as opaque `Passkey` blobs keyed by
raw credential id; signature counters and backup state are persisted after
each login for clone detection. The ceremony state between start and finish
rides the encrypted cookie jar — no server-side session store needed.

The account page lists registered passkeys and allows deletion.
