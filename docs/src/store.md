# Implementing the store

Authery's only persistence interface is the `AutheryStore` trait. You
implement it over your database; authery never sees connection strings or
SQL. The two examples in the repo implement it over in-memory maps — a
Postgres implementation follows the same shape.

## Entities are traits

Each entity is a trait your concrete types implement, with associated ID
types satisfying `Id` (`Clone + Display + FromStr + PartialEq + ...` — Uuid
works out of the box, so do newtypes over it or over strings):

```rust,ignore
impl LoginSession for MySession {
    type Id = Uuid;
    type UserId = Uuid;
    fn get_id(&self) -> Uuid { self.id }
    fn get_user_id(&self) -> Uuid { self.user_id }
    fn get_method(&self) -> LoginMethod { self.method.clone() }
    fn get_expires(&self) -> DateTime<Utc> { self.expires }
}
```

Your types can carry any extra fields your app needs — authery only calls the
getters. `LoginMethod` should be persisted as an opaque serializable value
(it's `serde`-enabled); don't match on it in the store.

## Semantics that matter

A few store methods carry security-relevant contracts:

- `email_consume_challenge` must fetch **and delete** — challenges and codes
  are single-use.
- `create_session` ids act as bearer tokens: generate them with a CSPRNG
  (`Id::new_random` on Uuid does).
- `delete_session` / `delete_oauth_token` / `webauthn_delete_credential` are
  scoped by user id — verify ownership.
- `org`-like multi-tenant logic hooks in through
  `create_user_from_unmatched_token` / `get_user_by_unmatched_token`, which
  receive the oauth `context` and the **validated** id_token claims. See
  [organizations](organizations.md).

## The store is your extension point

Because the store is your code, it observes every user creation, login and
token exchange — that's where app-level side effects (provisioning, tenant
membership, analytics) belong, without authery needing hooks for each.
