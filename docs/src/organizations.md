# Multi-tenancy: organizations on top of authery

Authery deliberately has no organizations feature. Orgs — members, roles,
invites, billing, admin pages — are app domain, and your app will model them
better than a library can. What your app *cannot* build alone is the auth
plumbing for per-tenant SSO: the PKCE/nonce/state-cookie dance against a
provider that isn't known until request time. That's the primitive authery
provides, and this chapter builds a complete "Anthropic-style" org setup on
it. The `memory-store` example contains the full working code, verified
against Keycloak.

## The three primitives

1. **A provider resolver** — providers looked up from *your* tables at
   request time, keyed by an opaque context string (here: the org slug).
2. **Context-carrying flows** — `oauth_login_init_with_context` puts the
   context in the encrypted state cookie; the callback resolves the provider
   through your resolver again.
3. **The context on the token** — your store's
   `create_user_from_unmatched_token` / `get_user_by_unmatched_token` receive
   `UnmatchedOAuthToken { context, provider_user_raw: validated_claims, .. }`.
   That's your membership hook.

## 1. Your org tables

Plain app types — authery never sees them:

```rust,ignore
struct AppOrg { id: Uuid, slug: String, name: String, login_rules: LoginMethodRules }
struct AppOrgMember { user_id: Uuid, org_id: Uuid, admin: bool }
struct AppOrgProvider { org_id: Uuid, name: String, client_id: String, /* secret, issuer, urls */ }
```

## 2. The resolver

```rust,ignore
impl OAuthProviderResolver for AppProviderResolver {
    fn resolve<'a>(&'a self, context: &'a str, provider_name: &'a str)
        -> ProviderResolverFuture<'a>
    {
        Box::pin(async move {
            let Some(p) = self.db.org_provider(context, provider_name).await else {
                return Ok(None);
            };
            // The org's IdP is authoritative: whoever it authenticates gets in,
            // so login and signup are interchangeable for this provider.
            Ok(Some(Arc::new(
                OAuthOidcProvider::new(&p.name, &p.display_name, &p.client_id,
                    &p.client_secret, &p.issuer, &p.auth_url, &p.token_url, &["openid"])?
                    .with_allow_signup(Some(Allow::OnEither))
                    .with_allow_login(Some(Allow::OnEither)),
            ) as Arc<dyn OAuthProvider>))
        })
    }
}

OAuthConfig::new(base_url).with_provider_resolver(AppProviderResolver { db })
```

## 3. The org login page & flow start

An app route, in your design, listing providers from your tables:

```rust,ignore
// GET /login/{org} renders the org's providers;
// POST /login/{org} starts the flow with the slug as context:
match auth.oauth_login_init_with_context(slug, &form.provider, next).await {
    Ok((auth, url)) => (auth, Redirect::to(url.as_str())).into_response(),
    Err(err) => /* redirect back with error */,
}
```

## 4. Membership on login

Your store observes the completed flow — context plus **validated** id_token
claims — and applies your rules. Claim mapping is ordinary code:

```rust,ignore
async fn apply_org_context(&self, token: &UnmatchedOAuthToken, user_id: Uuid) {
    let Some(slug) = token.context.as_deref() else { return };
    let Some(org) = self.org_by_slug(slug).await else { return };

    let admin = token.provider_user_raw["realm_access"]["roles"]
        .as_array()
        .is_some_and(|r| r.iter().any(|r| r.as_str() == Some("acme-admin")));

    self.upsert_member(org.id, user_id, admin).await;
}
```

Call it from both `get_user_by_unmatched_token` (returning members) and
`create_user_from_unmatched_token` (first login). This is also where you'd
suppress private-workspace provisioning for invited users, sync role
revocations, etc.

## 5. Gating org routes

Membership is your table; login-method policy is a `LoginMethodRules` check:

```rust,ignore
if !org.login_rules.satisfies(&session.get_method()) {
    return StatusCode::FORBIDDEN; // e.g. this org requires MFA
}
let Some(member) = self.member(org.id, session.get_user_id()).await else {
    return StatusCode::FORBIDDEN;
};
```

## What about invites, private workspaces, sub-orgs?

All expressible without authery's involvement: invites are a signed cookie or
query token your post-login landing page consumes (the user is authenticated
by then); private workspaces are provisioned wherever your store creates
users; org trees and role inheritance are queries over your own tables. The
auth crate's job ended when the session was minted and your store was handed
the context.
