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
pub(crate) struct SharedCookieJar {
    pub(crate) jar: Arc<Mutex<PrivateCookieJar>>,
    /// Read-only jars over the same request headers, one per previous
    /// cookie key - the key-rotation grace path.
    pub(crate) fallbacks: Arc<Vec<PrivateCookieJar>>,
}

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
    /// Previous-key jars consulted when the current key can't decrypt a
    /// cookie; hits are re-encrypted under the current key on the way out.
    pub(crate) fallbacks: Arc<Vec<PrivateCookieJar>>,
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

impl AxumAutheryCookies {
    fn put(&mut self, cookie: Cookie<'static>) {
        match &mut self.jar {
            JarHandle::Owned(jar) => *jar = jar.clone().add(cookie),
            JarHandle::Shared(shared) => {
                let mut jar = shared.jar.lock().unwrap();
                *jar = jar.clone().add(cookie);
            }
        }
    }
}

impl AutheryCookies for AxumAutheryCookies {
    fn add(&mut self, key: &str, value: &str) {
        let cookie = self.build_cookie(key, value);
        self.put(cookie);
    }

    fn add_persistent(&mut self, key: &str, value: &str, max_age: chrono::Duration) {
        let mut cookie = self.build_cookie(key, value);
        cookie.unset_expires();
        cookie.set_max_age(time::Duration::seconds(max_age.num_seconds().max(0)));
        self.put(cookie);
    }

    fn get(&self, key: &str) -> Option<String> {
        let primary = match &self.jar {
            JarHandle::Owned(jar) => jar.get(key).map(|c| c.value().to_owned()),
            JarHandle::Shared(shared) => shared
                .jar
                .lock()
                .unwrap()
                .get(key)
                .map(|c| c.value().to_owned()),
        };
        if primary.is_some() {
            return primary;
        }

        // Key rotation: cookies sealed with a previous key still decrypt,
        // and get re-encrypted under the current key when we can write.
        for fallback in self.fallbacks.iter() {
            if let Some(cookie) = fallback.get(key) {
                let value = cookie.value().to_owned();
                if let JarHandle::Shared(shared) = &self.jar {
                    let reencrypted = self.build_cookie(key, &value);
                    let mut jar = shared.jar.lock().unwrap();
                    *jar = jar.clone().add(reencrypted);
                }
                return Some(value);
            }
        }

        None
    }

    fn remove(&mut self, key: &str) {
        // The removal cookie must carry the same Path (and domain) as the
        // original or the browser won't match it and the cookie survives.
        let cookie = self.build_cookie(key, "");
        match &mut self.jar {
            JarHandle::Owned(jar) => *jar = jar.clone().remove(cookie),
            JarHandle::Shared(shared) => {
                let mut jar = shared.jar.lock().unwrap();
                *jar = jar.clone().remove(cookie);
            }
        }
    }

    fn list_encoded(&self) -> Vec<String> {
        match &self.jar {
            JarHandle::Owned(jar) => jar.iter().map(|c| c.encoded().to_string()).collect(),
            JarHandle::Shared(shared) => shared
                .jar
                .lock()
                .unwrap()
                .iter()
                .map(|c| c.encoded().to_string())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum_extra::extract::cookie::Key;

    /// A cookie sealed under a previous key is readable through the fallback
    /// jars and re-encrypted under the current key on the way out.
    #[test]
    fn previous_key_cookies_are_read_and_reencrypted() {
        let old_key = Key::from(&[1u8; 64]);
        let new_key = Key::from(&[2u8; 64]);

        // Seal a cookie under the OLD key and capture its wire form.
        let sealed = PrivateCookieJar::new(old_key.clone())
            .add(Cookie::build(("test-cookie", "hello")).path("/").build());
        let response = (sealed, "").into_response();
        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let wire = set_cookie.split(';').next().unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::COOKIE, wire.parse().unwrap());

        // The NEW key alone cannot read it...
        let primary = PrivateCookieJar::from_headers(&headers, new_key.clone());
        assert!(primary.get("test-cookie").is_none());

        // ...but with the old key as a fallback, the value comes through and
        // gets re-encrypted into the (shared) primary jar.
        let shared = SharedCookieJar {
            jar: Arc::new(Mutex::new(primary)),
            fallbacks: Arc::new(vec![PrivateCookieJar::from_headers(&headers, old_key)]),
        };
        let cookies = AxumAutheryCookies {
            jar: JarHandle::Shared(shared.clone()),
            fallbacks: shared.fallbacks.clone(),
            https_only: false,
        };

        assert_eq!(cookies.get("test-cookie").as_deref(), Some("hello"));
        assert_eq!(
            shared
                .jar
                .lock()
                .unwrap()
                .get("test-cookie")
                .map(|c| c.value().to_string())
                .as_deref(),
            Some("hello"),
            "re-encrypted under the current key"
        );
    }
}
