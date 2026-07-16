# Login methods

Every method produces the same thing: a login session whose `LoginMethod`
records how it was created (including both factors for MFA sessions). Your
app can inspect the method — e.g. with [`LoginMethodRules`](mfa.md) — to
demand stronger login for sensitive routes.

- [Passwords](password.md)
- [Email links & one-time codes](email.md)
- [OAuth2 & OIDC](oauth.md)
- [Passkeys (WebAuthn)](webauthn.md)
- [Multi-factor authentication](mfa.md)
