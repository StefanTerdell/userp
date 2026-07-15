# Authery

Authery is a composable auth system with OAuth/OIDC, password and email support, and a ready-made Axum router with replaceable pages.

Everything is behind cargo features - enable only what you need:

- `user` - account management (sessions, emails, linked logins)
- `email` - magic links, verification and password resets
- `password` - classic password login/signup
- `oauth` - OAuth2/OIDC login, signup, linking and token refresh
- `pages` - included Askama pages for login, signup and account management
- `axum` - Axum extractors, cookie handling and the built-in router

See the `examples/` directory in the repository for full usage.
