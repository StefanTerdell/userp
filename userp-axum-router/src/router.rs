#[cfg(feature = "account")]
pub mod account;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth-callbacks")]
pub mod oauth;
#[cfg(feature = "pages")]
pub mod pages;
#[cfg(feature = "password")]
pub mod password;

use axum::{
    extract::FromRef,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use userp_client::routes::Routes;
use userp_server::{config::UserpConfig, store::UserpStore, Userp as AxumUserp};

pub trait AxumRouter {
    fn routes(&self) -> &Routes;

    fn router<St, S>(&self) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        router = router
            .route(self.routes().logout.as_str(), get(get_user_logout::<St>))
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

            #[cfg(feature = "account")]
            {
                router = router.route(
                    self.routes().pages.user.as_str(),
                    get(pages::get_user::<St>),
                );
            }
        }

        #[cfg(feature = "account")]
        {
            router = router
                .route(
                    self.routes().account.user_delete.as_str(),
                    post(account::post_user_delete::<St>),
                )
                .route(
                    self.routes().account.user_session_delete.as_str(),
                    post(account::post_user_session_delete::<St>),
                );

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes().account.user_password_set.as_str(),
                        post(account::post_user_password_set::<St>),
                    )
                    .route(
                        self.routes().account.user_password_delete.as_str(),
                        post(account::post_user_password_delete::<St>),
                    );
            }

            #[cfg(feature = "oauth-callbacks")]
            {
                router = router.route(
                    self.routes().account.user_oauth_delete.as_str(),
                    post(account::post_user_oauth_delete::<St>),
                );
            }

            #[cfg(feature = "email")]
            {
                router = router
                    .route(
                        self.routes().account.user_email_add.as_str(),
                        post(account::post_user_email_add::<St>),
                    )
                    .route(
                        self.routes().account.user_email_delete.as_str(),
                        post(account::post_user_email_delete::<St>),
                    )
                    .route(
                        self.routes().account.user_email_enable_login.as_str(),
                        post(account::post_user_email_enable_login::<St>),
                    )
                    .route(
                        self.routes().account.user_email_disable_login.as_str(),
                        post(account::post_user_email_disable_login::<St>),
                    );
            }
        }

        #[cfg(feature = "oauth-callbacks")]
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

        router
    }
}

impl AxumRouter for UserpConfig {
    fn routes(&self) -> &Routes {
        &self.routes
    }
}

async fn get_user_logout<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.pages.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)))
}

async fn get_user_verify_session<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}
