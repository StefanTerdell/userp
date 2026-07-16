use super::cookies::{AxumAutheryCookies, JarHandle, SharedCookieJar};
use crate::{config::AutheryConfig, core::CoreAuthery, store::AutheryStore};
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

        // When the cookie-propagation middleware is present it has already built
        // the jar and shared it via request extensions; use that so mutations
        // survive to the response without the handler returning the auth service.
        // Otherwise fall back to an owned jar written via IntoResponseParts.
        let jar = match parts.extensions.get::<SharedCookieJar>() {
            Some(shared) => JarHandle::Shared(shared.clone()),
            None => JarHandle::Owned(PrivateCookieJar::from_headers(
                &parts.headers,
                Key::from(config.key.as_bytes()),
            )),
        };

        let cookies = AxumAutheryCookies {
            jar,
            https_only: config.https_only,
        };
        let store = St::from_ref(state);

        Ok(CoreAuthery {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            session_lifetime: config.session_lifetime,
            rate_limiter: config.rate_limiter,
            routes: config.routes,
            cookies,
            store,
            #[cfg(feature = "email")]
            email: config.email,
            #[cfg(feature = "password")]
            pass: config.pass,
            #[cfg(feature = "oauth")]
            oauth: config.oauth,
            #[cfg(feature = "pages")]
            pages: config.pages,
        })
    }
}
