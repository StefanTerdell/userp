use crate::models::AutheryCookies;
use axum::response::IntoResponseParts;
use axum_extra::extract::cookie::{Cookie, Expiration, PrivateCookieJar, SameSite};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

/// A cookie jar shared between the [`cookie_layer`](super::router::cookie_layer)
/// middleware and the request handler. The handler mutates it through the
/// extracted auth service; the middleware serializes it onto the response after
/// the handler returns, so handlers no longer have to return the auth service to
/// persist cookies.
#[derive(Clone)]
pub(crate) struct SharedCookieJar(pub(crate) Arc<Mutex<PrivateCookieJar>>);

/// Either a jar shared with the cookie-propagation middleware, or one owned by
/// the auth service. Owned mode preserves the older pattern where a handler
/// returns the auth service to write cookies; shared mode makes that automatic.
#[derive(Clone)]
pub(crate) enum JarHandle {
    Shared(SharedCookieJar),
    Owned(PrivateCookieJar),
}

#[derive(Clone)]
pub struct AxumAutheryCookies {
    pub(crate) jar: JarHandle,
    pub(crate) https_only: bool,
}

impl IntoResponseParts for AxumAutheryCookies {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        match self.jar {
            // The middleware owns serialization in shared mode, so returning the
            // auth service from a handler is a harmless no-op.
            JarHandle::Shared(_) => Ok(res),
            JarHandle::Owned(jar) => jar.into_response_parts(res),
        }
    }
}

impl AxumAutheryCookies {
    fn build_cookie(&self, key: &str, value: &str) -> Cookie<'static> {
        Cookie::build((key.to_owned(), value.to_owned()))
            .same_site(SameSite::Lax)
            .http_only(true)
            .expires(Expiration::Session)
            .secure(self.https_only)
            .path("/")
            .build()
    }
}

impl AutheryCookies for AxumAutheryCookies {
    fn add(&mut self, key: &str, value: &str) {
        let cookie = self.build_cookie(key, value);
        match &mut self.jar {
            JarHandle::Owned(jar) => *jar = jar.clone().add(cookie),
            JarHandle::Shared(shared) => {
                let mut jar = shared.0.lock().unwrap();
                *jar = jar.clone().add(cookie);
            }
        }
    }

    fn get(&self, key: &str) -> Option<String> {
        match &self.jar {
            JarHandle::Owned(jar) => jar.get(key).map(|c| c.value().to_owned()),
            JarHandle::Shared(shared) => shared
                .0
                .lock()
                .unwrap()
                .get(key)
                .map(|c| c.value().to_owned()),
        }
    }

    fn remove(&mut self, key: &str) {
        // The removal cookie must carry the same Path (and domain) as the
        // original or the browser won't match it and the cookie survives.
        let cookie = self.build_cookie(key, "");
        match &mut self.jar {
            JarHandle::Owned(jar) => *jar = jar.clone().remove(cookie),
            JarHandle::Shared(shared) => {
                let mut jar = shared.0.lock().unwrap();
                *jar = jar.clone().remove(cookie);
            }
        }
    }

    fn list_encoded(&self) -> Vec<String> {
        match &self.jar {
            JarHandle::Owned(jar) => jar.iter().map(|c| c.encoded().to_string()).collect(),
            JarHandle::Shared(shared) => shared
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|c| c.encoded().to_string())
                .collect(),
        }
    }
}
