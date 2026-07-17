# Live e2e helpers

Manual end-to-end verification against a running example app
(`cargo run` in `examples/memory-store` or `examples/postgres-store`, with
`docker compose -f dev/compose.yaml up -d` for Keycloak/Mailhog/Postgres).

- `webauthn.mjs` — registers a passkey and completes two concurrent
  usernameless login ceremonies through a headless-Chrome CDP virtual
  authenticator. Zero npm deps; needs node ≥ 22 and Chrome
  (`BASE=... CHROME=... node dev/e2e/webauthn.mjs`).
- `totp_gen.py` — prints the current RFC 6238 code for a base32 secret
  (`python3 dev/e2e/totp_gen.py <SECRET> [step-offset]`), for driving the
  authenticator-app flows from curl.

Codes sent by email land in Mailhog (http://localhost:8025); the examples'
dev SMS sender prints texts to stdout.
