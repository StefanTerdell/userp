use crate::models::AutheryCookies;
use axum::response::IntoResponseParts;
use axum_extra::extract::cookie::{Cookie, Expiration, PrivateCookieJar, SameSite};
use std::convert::Infallible;

#[derive(Debug, Clone)]
pub struct AxumAutheryCookies {
    pub(crate) jar: PrivateCookieJar,
    pub(crate) https_only: bool,
}

impl IntoResponseParts for AxumAutheryCookies {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

impl AutheryCookies for AxumAutheryCookies {
    fn add(&mut self, key: &str, value: &str) {
        self.jar = self.jar.clone().add(
            Cookie::build((key.to_owned(), value.to_owned()))
                .same_site(SameSite::Lax)
                .http_only(true)
                .expires(Expiration::Session)
                .secure(self.https_only)
                .path("/")
                .build(),
        );
    }

    fn get(&self, key: &str) -> Option<String> {
        self.jar.get(key).map(|c| c.value().to_owned())
    }

    fn remove(&mut self, key: &str) {
        self.jar = self.jar.clone().remove(key.to_owned());
    }

    fn list_encoded(&self) -> Vec<String> {
        self.jar.iter().map(|c| c.encoded().to_string()).collect()
    }
}
