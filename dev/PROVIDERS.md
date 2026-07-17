# Providers to configure for live testing

The memory-store example now picks up any provider whose `{NAME}_CLIENT_ID` +
`{NAME}_CLIENT_SECRET` env vars are set (it prints `oauth provider enabled: …`
at startup for each one it found). Nothing is required — configure whichever
you want tested and start the example; the login page will show a button per
enabled provider.

Redirect/callback URL to register with every provider (the generic callback
handles login/signup/link/refresh in one):

    http://localhost:3000/login/oauth/{provider}/
    http://localhost:3000/signup/oauth/{provider}/

…where `{provider}` is the name in the table below. Some consoles only accept
one URL — register both if allowed, or just the login one for a login test.
Note the trailing slash (the redirect_uri builder appends it).

| Provider  | Env var prefix | Console | Notes |
|-----------|----------------|---------|-------|
| GitHub    | `GITHUB`    | github.com/settings/developers | Already existed; worth a re-test |
| GitLab    | `GITLAB`    | gitlab.com/-/user_settings/applications | Also has `GitLabOAuthProvider::new_oidc` (id_token validated) |
| Google    | `GOOGLE`    | console.cloud.google.com/apis/credentials | Already existed |
| Spotify   | `SPOTIFY`   | developer.spotify.com/dashboard | Already existed |
| Microsoft | `MICROSOFT` | portal.azure.com → App registrations | New. Uses `common` endpoint + Graph `/v1.0/me`; add platform "Web", no implicit grant. Needs `User.Read` delegated permission (default) |
| Discord   | `DISCORD`   | discord.com/developers/applications | New. OAuth2 → add redirect |
| Facebook  | `FACEBOOK`  | developers.facebook.com/apps | New. Add "Facebook Login" product; app in dev mode only allows app admins/testers to log in |
| Twitch    | `TWITCH`    | dev.twitch.tv/console/apps | New. Category: Website Integration |
| Slack     | `SLACK`     | api.slack.com/apps | New. Uses "Sign in with Slack" (OpenID Connect); enable it and add the redirect under OAuth & Permissions. Slack requires HTTPS redirect URLs — use a tunnel (e.g. `ngrok`, `cloudflared`) or test another provider first |
| LinkedIn  | `LINKEDIN`  | linkedin.com/developers/apps | New. Add product "Sign In with LinkedIn using OpenID Connect" |
| X         | `X`         | developer.x.com (Projects & Apps) | New. OAuth 2.0, type "Web App" (confidential). Free tier is heavily rate-limited but enough for a login test |

## SMS providers

The `sms` feature ships ready-made senders (Twilio, Vonage, MessageBird,
Telnyx, 46elks); any `SmsSender` impl works too. The example
wires up two of them by env, falling back to a dev sender that just prints
the text to stdout (so SMS login is fully testable with no account at all —
the code also shows up in the challenges on `/store`):

| Provider | Env vars | Console | Notes |
|----------|----------|---------|-------|
| Twilio   | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` | console.twilio.com | Trial accounts can only text verified numbers |
| 46elks   | `ELKS_USERNAME`, `ELKS_PASSWORD`, `ELKS_FROM` | 46elks.com/account | Swedish, cheap, no from-number needed (alphanumeric sender works) |

The other three (`VonageSmsSender`, `MessageBirdSmsSender`,
`TelnyxSmsSender`) are exported from the prelude and take their credentials
as plain constructor args — add an env branch in `main.rs` if you want one
of them live-tested.

Deliberately deferred:

- **Apple** — "Sign in with Apple" needs a JWT client secret generated from a
  team key (p8), i.e. real machinery rather than a static secret, plus an
  Apple Developer account and HTTPS. Worth its own work item if you want it.

Also useful while testing:

- Keycloak (docker: `docker compose -f dev/compose.yaml up -d`) covers the
  OIDC path with signature/nonce validation, including as an org provider on
  `/login/acme` — no external config needed.
- Mailhog (same compose file) covers email links, OTP codes, and MFA codes at
  http://localhost:8025.
