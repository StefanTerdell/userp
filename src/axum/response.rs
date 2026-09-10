//! Wire shapes shared by every handler, and the store-failure renderer.

use crate::store::StoreError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// `{ "error": … }`: rejections, refused ceremonies, rendered store errors.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct ApiError {
    /// What went wrong, in words meant for the end user.
    pub error: String,
}

impl ApiError {
    pub fn response(status: StatusCode, error: impl std::fmt::Display) -> Response {
        (
            status,
            Json(ApiError {
                error: error.to_string(),
            }),
        )
            .into_response()
    }
}

/// A flow step succeeded. Browsers get a redirect to `next`; JSON clients
/// get this.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct FlowResult {
    /// Where a browser would have been redirected to.
    pub next: String,
    /// A note worth showing the user, when the step produced one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A flow step was refused. `next` is where a browser would have been sent.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct FlowError {
    /// Why the step was refused.
    pub error: String,
    /// Where a browser would have been redirected to.
    pub next: String,
}

/// A store error on its way out of a handler. `?` converts the store's own
/// error into this via `From`; `IntoResponse` renders it safely.
#[derive(Debug)]
pub struct StoreFailure<E>(pub E);

impl<E> From<E> for StoreFailure<E> {
    fn from(err: E) -> Self {
        StoreFailure(err)
    }
}

/// What the cookie layer needs to swap the JSON body for a page when the
/// client is a browser. Attached to the response as an extension.
#[derive(Debug, Clone)]
pub(crate) struct StoreFailureInfo {
    pub status: StatusCode,
    pub message: String,
    /// Whether `message` came from the store's own [`crate::store::PublicError`]
    /// rather than being the generic stand-in. Only a public message may be
    /// shown on the error page.
    pub public: bool,
}

pub(crate) const INTERNAL_ERROR_MESSAGE: &str = "Internal server error";

/// What a secured endpoint says when there is no session. Shared by the
/// handlers and by the `401` entry their response sets document.
pub(crate) const NOT_LOGGED_IN: &str = "Not logged in.";

/// And what it says when a submitted entity id does not parse.
pub(crate) const MALFORMED_ID: &str = "Malformed id.";

impl<E: StoreError> IntoResponse for StoreFailure<E> {
    fn into_response(self) -> Response {
        tracing::error!(error = %self.0, "store error");
        let public = self.0.public();
        let is_public = public.is_some();
        let (status, message) = match public {
            Some(public) => (
                StatusCode::from_u16(public.status())
                    .ok()
                    .filter(|s| s.is_client_error() || s.is_server_error())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                public.message().to_string(),
            ),
            None => (
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR_MESSAGE.to_string(),
            ),
        };
        let mut res = ApiError::response(status, &message);
        res.extensions_mut().insert(StoreFailureInfo {
            status,
            message,
            public: is_public,
        });
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PublicError;
    use axum::body::to_bytes;

    #[derive(Debug)]
    struct Opted(Option<PublicError>);

    impl std::fmt::Display for Opted {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "store said no")
        }
    }

    impl std::error::Error for Opted {}

    impl StoreError for Opted {
        fn public(&self) -> Option<PublicError> {
            self.0.clone()
        }
    }

    async fn rendered(public: Option<PublicError>) -> (StatusCode, String) {
        let res = StoreFailure(Opted(public)).into_response();
        let status = res.status();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// A store may only opt into a status a client can be handed: anything
    /// outside `400..=599` is clamped to 500, message and all.
    #[tokio::test]
    async fn public_status_outside_the_error_range_is_clamped_to_500() {
        for status in [200u16, 999] {
            let (code, body) = rendered(Some(PublicError::new(status, "shown"))).await;
            assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR, "{status}");
            assert!(body.contains("shown"), "{status}: {body}");
        }

        let (code, body) = rendered(Some(PublicError::new(409, "That address is taken"))).await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert!(body.contains("That address is taken"), "{body}");

        let (code, body) = rendered(None).await;
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains(INTERNAL_ERROR_MESSAGE), "{body}");
    }
}
