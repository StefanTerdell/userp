#[cfg(feature = "user")]
pub mod user;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "otp")]
pub mod otp;
#[cfg(feature = "webauthn")]
pub mod webauthn;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "organizations")]
pub mod org;
#[cfg(feature = "pages")]
pub mod pages;
#[cfg(feature = "password")]
pub mod password;

use axum::{
    extract::{FromRef, Request},
    http::StatusCode,
    middleware::{from_fn, Next},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::sync::{Arc, Mutex};
use crate::axum::cookies::SharedCookieJar;
use crate::routes::Routes;
use crate::{config::AutheryConfig, store::AutheryStore, Authery as AxumAuthery};

/// Wraps `router` with middleware that builds the encrypted cookie jar once per
/// request, shares it with the handler via request extensions, and serializes it
/// onto the response afterwards. With this applied, handlers no longer need to
/// return the auth service to persist session cookies. The built-in
/// [`AxumRouter::router`] applies it automatically; call this yourself when
/// wiring authery handlers into a hand-rolled router.
pub fn with_cookie_layer<S>(router: Router<S>, key: Key) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(from_fn(move |mut req: Request, next: Next| {
        let key = key.clone();
        async move {
            let jar = PrivateCookieJar::from_headers(req.headers(), key);
            let shared = SharedCookieJar(Arc::new(Mutex::new(jar)));
            req.extensions_mut().insert(shared.clone());

            let res = next.run(req).await;

            let jar = shared.0.lock().unwrap().clone();
            (jar, res).into_response()
        }
    }))
}

/// Guards against open redirects: only local paths pass through,
/// anything absolute, protocol-relative or malformed becomes the fallback.
pub(crate) fn safe_next(next: Option<String>, fallback: &str) -> String {
    match next {
        Some(next)
            if next.starts_with('/')
                && !next.starts_with("//")
                && !next.starts_with("/\\")
                && !next.contains(|c: char| c.is_ascii_control()) =>
        {
            next
        }
        _ => fallback.to_string(),
    }
}

pub trait AxumRouter {
    fn routes(&self) -> &Routes;

    /// The cookie-encryption key, used to install the cookie-propagation layer.
    fn cookie_key(&self) -> Key;

    fn router<St, S>(&self) -> Router<S>
    where
        AutheryConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AutheryStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        router = router
            .route(self.routes().logout.as_str(), post(post_user_logout::<St>))
            .route(
                self.routes().user_verify_session.as_str(),
                get(get_user_verify_session::<St>),
            );

        #[cfg(feature = "pages")]
        {
            router = router
                .route(
                    self.routes().pages.login.as_str(),
                    get(pages::get_login::<St>),
                )
                .route(
                    self.routes().pages.signup.as_str(),
                    get(pages::get_signup::<St>),
                );

            // The org-scoped login page lives under the login page path;
            // static sibling routes (/login/email etc.) take precedence over
            // the capture.
            #[cfg(all(feature = "organizations", feature = "oauth"))]
            {
                router = router.route(
                    &format!("{}/{{org_slug}}", self.routes().pages.login),
                    get(pages::get_org_login::<St>),
                );
            }

            #[cfg(all(feature = "email", feature = "password"))]
            {
                router = router
                    .route(
                        self.routes().pages.password_send_reset.as_str(),
                        get(pages::get_password_send_reset::<St>),
                    )
                    .route(
                        self.routes().pages.password_reset.as_str(),
                        get(pages::get_password_reset::<St>),
                    );
            }

            #[cfg(feature = "user")]
            {
                router = router.route(
                    self.routes().pages.user.as_str(),
                    get(pages::get_user::<St>),
                );
            }
        }

        #[cfg(feature = "user")]
        {
            router = router
                .route(
                    self.routes().user.user_delete.as_str(),
                    post(user::post_user_delete::<St>),
                )
                .route(
                    self.routes().user.user_session_delete.as_str(),
                    post(user::post_user_session_delete::<St>),
                );

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes().user.user_password_set.as_str(),
                        post(user::post_user_password_set::<St>),
                    )
                    .route(
                        self.routes().user.user_password_delete.as_str(),
                        post(user::post_user_password_delete::<St>),
                    );
            }

            #[cfg(feature = "oauth")]
            {
                router = router.route(
                    self.routes().user.user_oauth_delete.as_str(),
                    post(user::post_user_oauth_delete::<St>),
                );
            }

            #[cfg(feature = "email")]
            {
                router = router
                    .route(
                        self.routes().user.user_email_add.as_str(),
                        post(user::post_user_email_add::<St>),
                    )
                    .route(
                        self.routes().user.user_email_delete.as_str(),
                        post(user::post_user_email_delete::<St>),
                    )
                    .route(
                        self.routes().user.user_email_enable_login.as_str(),
                        post(user::post_user_email_enable_login::<St>),
                    )
                    .route(
                        self.routes().user.user_email_disable_login.as_str(),
                        post(user::post_user_email_disable_login::<St>),
                    );
            }
        }

        #[cfg(feature = "oauth")]
        {
            #[cfg(feature = "oauth")]
            {
                router = router
                    .route(
                        self.routes().oauth.actions.login_oauth.as_str(),
                        post(oauth::post_login_oauth::<St>),
                    )
                    .route(
                        self.routes().oauth.actions.signup_oauth.as_str(),
                        post(oauth::post_signup_oauth::<St>),
                    )
                    .route(
                        self.routes().oauth.actions.user_oauth_link.as_str(),
                        post(oauth::post_user_oauth_link::<St>),
                    )
                    .route(
                        self.routes().oauth.actions.user_oauth_refresh.as_str(),
                        post(oauth::post_user_oauth_refresh::<St>),
                    );
            }

            if self.routes().oauth.callbacks.login_oauth_provider
                == self.routes().oauth.callbacks.signup_oauth_provider
                || self.routes().oauth.callbacks.login_oauth_provider
                    == self.routes().oauth.callbacks.user_oauth_link_provider
                || self.routes().oauth.callbacks.login_oauth_provider
                    == self.routes().oauth.callbacks.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes().oauth.callbacks.login_oauth_provider.as_str(),
                        get(oauth::get_generic_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .login_oauth_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes().oauth.callbacks.login_oauth_provider.as_str(),
                        get(oauth::get_login_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .login_oauth_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_login_oauth::<St>),
                    );
            }

            if self.routes().oauth.callbacks.signup_oauth_provider
                == self.routes().oauth.callbacks.login_oauth_provider
                || self.routes().oauth.callbacks.signup_oauth_provider
                    == self.routes().oauth.callbacks.user_oauth_link_provider
                || self.routes().oauth.callbacks.signup_oauth_provider
                    == self.routes().oauth.callbacks.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes().oauth.callbacks.signup_oauth_provider.as_str(),
                        get(oauth::get_generic_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .signup_oauth_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes().oauth.callbacks.signup_oauth_provider.as_str(),
                        get(oauth::get_signup_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .signup_oauth_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_signup_oauth::<St>),
                    );
            }

            if self.routes().oauth.callbacks.user_oauth_link_provider
                == self.routes().oauth.callbacks.signup_oauth_provider
                || self.routes().oauth.callbacks.user_oauth_link_provider
                    == self.routes().oauth.callbacks.login_oauth_provider
                || self.routes().oauth.callbacks.user_oauth_link_provider
                    == self.routes().oauth.callbacks.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes()
                            .oauth
                            .callbacks
                            .user_oauth_link_provider
                            .as_str(),
                        get(oauth::get_generic_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .user_oauth_link_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes()
                            .oauth
                            .callbacks
                            .user_oauth_link_provider
                            .as_str(),
                        get(oauth::get_user_oauth_link::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .user_oauth_link_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_user_oauth_link::<St>),
                    );
            }

            if self.routes().oauth.callbacks.user_oauth_refresh_provider
                == self.routes().oauth.callbacks.signup_oauth_provider
                || self.routes().oauth.callbacks.user_oauth_refresh_provider
                    == self.routes().oauth.callbacks.user_oauth_link_provider
                || self.routes().oauth.callbacks.user_oauth_refresh_provider
                    == self.routes().oauth.callbacks.login_oauth_provider
            {
                router = router
                    .route(
                        self.routes()
                            .oauth
                            .callbacks
                            .user_oauth_refresh_provider
                            .as_str(),
                        get(oauth::get_generic_oauth::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .user_oauth_refresh_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes()
                            .oauth
                            .callbacks
                            .user_oauth_refresh_provider
                            .as_str(),
                        get(oauth::get_user_oauth_refresh::<St>),
                    )
                    .route(
                        &(self
                            .routes()
                            .oauth
                            .callbacks
                            .user_oauth_refresh_provider
                            .to_owned()
                            + "/"),
                        get(oauth::get_user_oauth_refresh::<St>),
                    );
            }
        }

        #[cfg(feature = "password")]
        {
            router = router
                .route(
                    self.routes().password.login_password.as_str(),
                    post(password::post_login_password::<St>),
                )
                .route(
                    self.routes().password.signup_password.as_str(),
                    post(password::post_signup_password::<St>),
                );
        }

        #[cfg(feature = "webauthn")]
        {
            router = router
                .route(
                    self.routes().webauthn.login_webauthn_start.as_str(),
                    post(webauthn::post_login_webauthn_start::<St>),
                )
                .route(
                    self.routes().webauthn.login_webauthn_finish.as_str(),
                    post(webauthn::post_login_webauthn_finish::<St>),
                )
                .route(
                    self.routes().webauthn.user_webauthn_register_start.as_str(),
                    post(webauthn::post_user_webauthn_register_start::<St>),
                )
                .route(
                    self.routes()
                        .webauthn
                        .user_webauthn_register_finish
                        .as_str(),
                    post(webauthn::post_user_webauthn_register_finish::<St>),
                );

            #[cfg(feature = "user")]
            {
                router = router.route(
                    self.routes().webauthn.user_webauthn_delete.as_str(),
                    post(webauthn::post_user_webauthn_delete::<St>),
                );
            }
        }

        #[cfg(feature = "organizations")]
        {
            router = router
                .route(
                    self.routes().org.org_create.as_str(),
                    post(org::post_org_create::<St>),
                )
                .route(
                    self.routes().org.org_update.as_str(),
                    post(org::post_org_update::<St>),
                )
                .route(
                    self.routes().org.org_delete.as_str(),
                    post(org::post_org_delete::<St>),
                )
                .route(
                    self.routes().org.org_member_upsert.as_str(),
                    post(org::post_org_member_upsert::<St>),
                )
                .route(
                    self.routes().org.org_member_remove.as_str(),
                    post(org::post_org_member_remove::<St>),
                )
                .route(
                    self.routes().org.org_sub_create.as_str(),
                    post(org::post_org_sub_create::<St>),
                )
                .route(
                    self.routes().org.org_invite_create.as_str(),
                    post(org::post_org_invite_create::<St>),
                );

            #[cfg(feature = "oauth")]
            {
                router = router
                    .route(
                        self.routes().org.org_provider_upsert.as_str(),
                        post(org::post_org_provider_upsert::<St>),
                    )
                    .route(
                        self.routes().org.org_provider_delete.as_str(),
                        post(org::post_org_provider_delete::<St>),
                    );
            }

            #[cfg(feature = "pages")]
            {
                router = router
                    .route(self.routes().org.orgs.as_str(), get(org::get_orgs::<St>))
                    .route(self.routes().org.org.as_str(), get(org::get_org::<St>));
            }
        }

        #[cfg(feature = "mfa")]
        {
            #[cfg(feature = "pages")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa.as_str(),
                    get(pages::get_login_mfa::<St>),
                );
            }

            #[cfg(feature = "otp")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_otp.as_str(),
                    post(mfa::post_login_mfa_otp::<St>),
                );
            }

            #[cfg(feature = "webauthn")]
            {
                router = router
                    .route(
                        self.routes().mfa.login_mfa_webauthn_start.as_str(),
                        post(mfa::post_login_mfa_webauthn_start::<St>),
                    )
                    .route(
                        self.routes().mfa.login_mfa_webauthn_finish.as_str(),
                        post(mfa::post_login_mfa_webauthn_finish::<St>),
                    );
            }
        }

        #[cfg(feature = "email")]
        {
            router = router
                .route(
                    self.routes().email.login_email.as_str(),
                    post(email::post_login_email::<St>).get(email::get_login_email::<St>),
                )
                .route(
                    self.routes().email.signup_email.as_str(),
                    post(email::post_signup_email::<St>).get(email::get_signup_email::<St>),
                )
                .route(
                    self.routes().email.user_email_verify.as_str(),
                    post(email::post_user_email_verify::<St>)
                        .get(email::get_user_email_verify::<St>),
                );

            #[cfg(feature = "otp")]
            {
                let login_otp = post(otp::post_login_otp::<St>);
                let signup_otp = post(otp::post_signup_otp::<St>);

                // With pages active, GET on the same paths renders the
                // code-entry form.
                #[cfg(feature = "pages")]
                let login_otp = login_otp.get(pages::get_login_otp::<St>);
                #[cfg(feature = "pages")]
                let signup_otp = signup_otp.get(pages::get_signup_otp::<St>);

                router = router
                    .route(self.routes().email.login_otp.as_str(), login_otp)
                    .route(self.routes().email.signup_otp.as_str(), signup_otp);
            }

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes().email.password_reset.as_str(),
                        post(email::post_password_reset::<St>),
                    )
                    .route(
                        self.routes().email.password_reset_callback.as_str(),
                        get(email::get_password_reset_callback::<St>),
                    )
                    .route(
                        self.routes().email.password_send_reset.as_str(),
                        post(email::post_password_send_reset::<St>),
                    );
            }
        }

        with_cookie_layer(router, self.cookie_key())
    }
}

impl AxumRouter for AutheryConfig {
    fn routes(&self) -> &Routes {
        &self.routes
    }

    fn cookie_key(&self) -> Key {
        Key::from(self.key.as_bytes())
    }
}

async fn post_user_logout<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.pages.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)))
}

async fn get_user_verify_session<St>(auth: AxumAuthery<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AutheryStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}
