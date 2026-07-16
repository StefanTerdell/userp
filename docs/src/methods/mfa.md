# Multi-factor authentication

The `mfa` feature is a policy layer over the other methods. `MfaPolicy` names
the first factors that must be backed by a second one (default: passwords
only). When such a login succeeds *and the user has a second factor
registered*, the created session is **pending**: treated as logged-out
everywhere except the MFA completion flow, which offers

- a passkey ceremony scoped to the user's registered credentials, or
- a one-time code mailed to the user's **own verified address** — never one
  supplied in the request. Emailed codes are not offered when the first
  factor already proved control of the mailbox.

Completing the second factor replaces the pending session with one whose
method records both factors: `LoginMethod::Mfa { first, second }`.

Users without a registered factor log in normally — hard-requiring MFA at
login would lock out every fresh signup. Apps that want mandatory MFA steer
users to register a factor and gate sensitive routes:

```rust,ignore
let rules = LoginMethodRules { require_mfa: true, ..Default::default() };
if !rules.satisfies(&session.get_method()) {
    // send them to set up / complete MFA
}
```

`LoginMethodRules` counts two-factor sessions and single-factor passkeys
(possession + user verification) as satisfying `require_mfa`, and judges
`allow_password` / `allow_email` by the first factor.
