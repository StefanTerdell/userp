use super::cookies::AxumAutheryCookies;
use crate::{config::AutheryConfig, core::CoreAuthery, store::AutheryStore};
use axum::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::convert::Infallible;

impl<S: AutheryStore> IntoResponseParts for CoreAuthery<S, AxumAutheryCookies> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.cookies.into_response_parts(res)
    }
}

#[async_trait]
impl<S, St> FromRequestParts<S> for CoreAuthery<St, AxumAutheryCookies>
where
    St: AutheryStore,
    AutheryConfig: FromRef<S>,
    S: Send + Sync,
    St: AutheryStore + FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let config = AutheryConfig::from_ref(state);
        let cookies = AxumAutheryCookies {
            jar: PrivateCookieJar::from_headers(&parts.headers, Key::from(config.key.as_bytes())),
            https_only: config.https_only,
        };
        let store = St::from_ref(state);

        return Ok(CoreAuthery {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            routes: config.routes,
            cookies,
            store,
            #[cfg(feature = "email")]
            email: config.email,
            #[cfg(feature = "password")]
            pass: config.pass,
            #[cfg(feature = "oauth")]
            oauth: config.oauth,
        });
    }
}
