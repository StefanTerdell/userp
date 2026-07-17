#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "otp")]
pub mod otp;
#[cfg(feature = "pages")]
pub mod pages;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "sms")]
pub mod sms;
#[cfg(feature = "user")]
pub mod user;
#[cfg(feature = "webauthn")]
pub mod webauthn;

use crate::axum::cookies::SharedCookieJar;
use crate::routes::Routes;
use crate::{Authery as AxumAuthery, config::AutheryConfig, store::AutheryStore};
use axum::{
    Router,
    extract::{FromRef, Request},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::sync::{Arc, Mutex};

/// Wraps `router` with middleware that builds the encrypted cookie jar once per
/// request, shares it with the handler via request extensions, and serializes it
/// onto the response afterwards. With this applied, handlers no longer need to
/// return the auth service to persist session cookies. The built-in
/// [`AxumRouter::router`] applies it automatically; call this yourself when
/// wiring authery handlers into a hand-rolled router.
///
/// With `expose_auth_token` (the [`crate::config::AutheryConfig::bearer_auth`]
/// setting), a request that establishes a NEW session also gets an
/// `X-Auth-Token` response header carrying the session id, so non-browser
/// clients can capture it and authenticate with
/// `Authorization: Bearer {token}` from then on.
pub fn with_cookie_layer<S>(router: Router<S>, key: Key, expose_auth_token: bool) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(from_fn(move |mut req: Request, next: Next| {
        let key = key.clone();
        async move {
            let jar = PrivateCookieJar::from_headers(req.headers(), key);
            let session_before = jar
                .get(crate::constants::SESSION_ID_KEY)
                .map(|c| c.value().to_string());
            let shared = SharedCookieJar(Arc::new(Mutex::new(jar)));
            req.extensions_mut().insert(shared.clone());

            let res = next.run(req).await;

            let jar = shared.0.lock().unwrap().clone();
            let session_after = jar
                .get(crate::constants::SESSION_ID_KEY)
                .map(|c| c.value().to_string());

            let mut res = (jar, res).into_response();

            if expose_auth_token
                && session_after != session_before
                && let Some(token) = session_after
                && let Ok(value) = token.parse()
            {
                res.headers_mut().insert("x-auth-token", value);
            }

            res
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

    /// Whether bearer-token auth is enabled (exposes `X-Auth-Token` on fresh
    /// logins); see [`crate::config::AutheryConfig::bearer_auth`].
    fn bearer_auth(&self) -> bool {
        false
    }

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

            #[cfg(feature = "totp")]
            {
                router = router
                    .route(
                        self.routes().user.user_totp_confirm.as_str(),
                        post(user::post_user_totp_confirm::<St>),
                    )
                    .route(
                        self.routes().user.user_totp_disable.as_str(),
                        post(user::post_user_totp_disable::<St>),
                    );

                #[cfg(feature = "pages")]
                {
                    router = router.route(
                        self.routes().user.user_totp_enroll.as_str(),
                        post(user::post_user_totp_enroll::<St>),
                    );
                }
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

            #[cfg(feature = "totp")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_totp.as_str(),
                    post(mfa::post_login_mfa_totp::<St>),
                );
            }

            #[cfg(feature = "sms")]
            {
                router = router.route(
                    self.routes().mfa.login_mfa_sms.as_str(),
                    post(mfa::post_login_mfa_sms::<St>),
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

        #[cfg(feature = "sms")]
        {
            let login_sms = post(sms::post_login_sms::<St>);
            let signup_sms = post(sms::post_signup_sms::<St>);

            #[cfg(feature = "pages")]
            let login_sms = login_sms.get(pages::get_login_sms::<St>);
            #[cfg(feature = "pages")]
            let signup_sms = signup_sms.get(pages::get_signup_sms::<St>);

            router = router
                .route(self.routes().sms.login_sms.as_str(), login_sms)
                .route(self.routes().sms.signup_sms.as_str(), signup_sms);
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

        with_cookie_layer(router, self.cookie_key(), self.bearer_auth())
    }
}

impl AxumRouter for AutheryConfig {
    fn routes(&self) -> &Routes {
        &self.routes
    }

    fn cookie_key(&self) -> Key {
        Key::from(self.key.as_bytes())
    }

    fn bearer_auth(&self) -> bool {
        self.bearer_auth
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
