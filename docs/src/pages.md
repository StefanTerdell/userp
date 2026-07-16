# Pages & templates

The `pages` feature bundles Askama templates for login, signup, the account
page, password reset, OTP entry and the MFA picker. They're intentionally
plain — restyle or replace them.

## Replacing the pages

Implement the `Pages` trait and register it:

```rust,ignore
#[derive(Debug)]
struct MyPages;

impl Pages for MyPages {
    fn render_login(&self, view: &LoginTemplate<'_>) -> String {
        // `view` carries every route, provider list and flag the page needs —
        // render it with whatever templating you like.
        my_render("login", view)
    }
    // ... one method per page
}

AutheryConfig::new(...)?.with_pages(MyPages)
```

Each method receives the same public view-model the bundled template sees
(`LoginTemplate`, `SignupTemplate`, `UserTemplate`, ...), so you keep the
router and flows while owning the markup.

## Skipping pages entirely

Don't enable `pages`: the router then serves only the action/callback
endpoints, and you build the UI yourself — the
`memory-store-password-only-no-templates` example shows this. The view-model
constructors (`LoginTemplate::with(...)` etc.) remain available if you want
the prepared data without the bundled HTML.

Note for passkeys/MFA: those pages carry small inline scripts driving the
`navigator.credentials` ceremonies against authery's JSON endpoints — if you
replace the pages, bring equivalent glue (the bundled templates are the
reference).
