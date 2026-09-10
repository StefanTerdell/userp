//! aide integration: authery's extractors and response types describe
//! themselves, so [`AxumRouter::api_router`](crate::axum::router::AxumRouter::api_router)
//! can register every endpoint through aide's typed routing and have
//! `finish_api` document them alongside the application's own routes.
//!
//! aide owns the schema generator here, so nothing goes through
//! [`crate::openapi::Document`]: request bodies come from the
//! [`OperationInput`] impls below and everything else from the endpoint
//! table's `ResponseSet` through [`Endpoint::transform_aide`].

use crate::axum::extract::{FormOrJson, WebauthnJson};
use crate::axum::response::{ApiError, FlowError, FlowResult, StoreFailure};
use crate::axum::router::CookieLayered;
use crate::axum::router::endpoint::{
    Body, CHALLENGE, CREDENTIAL, Endpoint, INTERNAL_ERROR, STORE_REFUSED, Status,
};
use crate::openapi::{AUTH_TOKEN_HEADER, AUTH_TOKEN_HEADER_DESCRIPTION, Describe};
use crate::store::AutheryStore;
use aide::{
    OperationInput, OperationOutput,
    generate::{GenContext, in_context},
    openapi::{
        Header, MediaType, Operation, ParameterSchemaOrContent, ReferenceOr, RequestBody, Response,
        SchemaObject, SecurityScheme, StatusCode,
    },
    transform::TransformOperation,
};
use axum::{
    extract::Request,
    middleware::{Next, from_fn},
    response::Response as HandlerResponse,
};
use schemars::JsonSchema;

// --- Extractors ------------------------------------------------------------

/// The auth service is built from cookies and headers alone: nothing to
/// document, but it has to be describable for handlers to be routable.
impl<St: AutheryStore> OperationInput for crate::axum::AxumAuthery<St> {}

/// Both media types, one shared schema — matching what the extractor accepts.
impl<T: JsonSchema> OperationInput for FormOrJson<T> {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        let media = MediaType {
            schema: Some(SchemaObject {
                json_schema: ctx.schema.subschema_for::<T>(),
                example: None,
                external_docs: None,
            }),
            ..Default::default()
        };
        let mut body = RequestBody {
            required: true,
            ..Default::default()
        };
        body.content
            .insert(crate::openapi::FORM.into(), media.clone());
        body.content.insert(crate::openapi::JSON.into(), media);
        aide::operation::set_body(ctx, operation, body);
    }
}

/// The W3C credential payloads carry no schema of their own.
impl<T> OperationInput for WebauthnJson<T> {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        let mut body = RequestBody {
            required: true,
            ..Default::default()
        };
        body.content
            .insert(crate::openapi::JSON.into(), opaque_media(CREDENTIAL));
        aide::operation::set_body(ctx, operation, body);
    }
}

/// An `application/json` media type around an opaque W3C object.
fn opaque_media(description: &str) -> MediaType {
    MediaType {
        schema: Some(SchemaObject {
            json_schema: Describe::opaque_object(description),
            example: None,
            external_docs: None,
        }),
        ..Default::default()
    }
}

// --- Responses -------------------------------------------------------------

/// The wire shapes are documented exactly as `Json<T>` would be, so they can
/// be named directly in [`TransformOperation::response_with`].
macro_rules! json_output {
    ($ty:ty) => {
        impl OperationOutput for $ty {
            type Inner = $ty;

            fn operation_response(ctx: &mut GenContext, op: &mut Operation) -> Option<Response> {
                axum::Json::<$ty>::operation_response(ctx, op)
            }
        }
    };
}

json_output!(FlowResult);
json_output!(FlowError);
json_output!(ApiError);

/// A store error always leaves as `500 ApiError` unless the store opted into
/// a public status, which the `4XX` response covers.
impl<E> OperationOutput for StoreFailure<E> {
    type Inner = ApiError;

    fn operation_response(ctx: &mut GenContext, op: &mut Operation) -> Option<Response> {
        axum::Json::<ApiError>::operation_response(ctx, op).map(|mut res| {
            res.description = INTERNAL_ERROR.description.into();
            res
        })
    }

    fn inferred_responses(
        ctx: &mut GenContext,
        op: &mut Operation,
    ) -> Vec<(Option<StatusCode>, Response)> {
        Self::operation_response(ctx, op)
            .map(|res| vec![(Some(StatusCode::Code(500)), res)])
            .unwrap_or_default()
    }
}

// --- Operations ------------------------------------------------------------

impl Body {
    /// This body as an aide response, description left blank.
    fn aide_response(&self, ctx: &mut GenContext) -> Response {
        // `operation_response` takes the operation only to report errors on
        // it; none of the impls used here touch it.
        let scratch = &mut Operation::default();
        let response = match self {
            Body::None => None,
            Body::FlowResult => axum::Json::<FlowResult>::operation_response(ctx, scratch),
            Body::FlowError => axum::Json::<FlowError>::operation_response(ctx, scratch),
            Body::ApiError => axum::Json::<ApiError>::operation_response(ctx, scratch),
            Body::Html => axum::response::Html::<String>::operation_response(ctx, scratch),
            Body::Challenge => {
                let mut response = Response::default();
                response
                    .content
                    .insert(crate::openapi::JSON.into(), opaque_media(CHALLENGE));
                Some(response)
            }
        };
        response.unwrap_or_default()
    }
}

impl From<Status> for StatusCode {
    fn from(status: Status) -> Self {
        match status {
            Status::Code(code) => StatusCode::Code(code),
            Status::Range(class) => StatusCode::Range(class),
        }
    }
}

impl Endpoint {
    /// The whole operation, from the same table [`Endpoint::describe`] reads:
    /// summary, tag and id from the row, responses from its `ResponseSet`,
    /// security from its `secured` column. `bearer` is the config's
    /// [`crate::config::AutheryConfig::bearer_auth`] setting, which decides
    /// both the `X-Auth-Token` header and the bearer security alternative.
    pub(crate) fn transform_aide<'t>(
        &self,
        bearer: bool,
        op: TransformOperation<'t>,
    ) -> TransformOperation<'t> {
        // The cookie layer emits `X-Auth-Token` exactly when the session
        // cookie changes, which is what the row's `establishes_session`
        // column records - including the MFA completion POSTs, which
        // require a pending session and still rotate it into a real one.
        let token = bearer && self.establishes_session();

        let mut op = op.id(self.name()).summary(self.summary()).tag(self.tag());

        // `INTERNAL_ERROR` is left out: `StoreFailure`'s inferred response has
        // already put it on the operation, with the same description.
        let mut built = Vec::new();
        in_context(|ctx| {
            for doc in self
                .response_set()
                .responses()
                .iter()
                .chain([&STORE_REFUSED])
            {
                let mut response = doc.body.aide_response(ctx);
                response.description = doc.description.into();
                if doc.token && token {
                    response.headers.insert(
                        AUTH_TOKEN_HEADER.into(),
                        ReferenceOr::Item(auth_token_header()),
                    );
                }
                built.push((StatusCode::from(doc.status), response));
            }
        });

        let responses = op
            .inner_mut()
            .responses
            .get_or_insert_with(Default::default);
        for (status, response) in built {
            responses
                .responses
                .insert(status, ReferenceOr::Item(response));
        }

        if self.secured() {
            op = op.security_requirement("session_cookie");
            if bearer {
                op = op.security_requirement("bearer");
            }
        }

        op
    }
}

/// The `X-Auth-Token` header, as aide models it.
fn auth_token_header() -> Header {
    Header {
        description: Some(AUTH_TOKEN_HEADER_DESCRIPTION.into()),
        style: Default::default(),
        required: false,
        deprecated: None,
        format: ParameterSchemaOrContent::Schema(SchemaObject {
            json_schema: schemars::json_schema!({ "type": "string" }),
            example: None,
            external_docs: None,
        }),
        example: None,
        examples: Default::default(),
        extensions: Default::default(),
    }
}

/// The security schemes the operations refer to. aide collects components
/// from the schema generator only, so these have to be inserted into
/// `api.components.security_schemes` after `finish_api`; see
/// [`crate::axum::router::AxumRouter::aide_security_schemes`].
pub(crate) fn security_schemes(
    bearer: bool,
    session_cookie: String,
) -> Vec<(String, SecurityScheme)> {
    let mut out = vec![(
        "session_cookie".to_string(),
        SecurityScheme::ApiKey {
            location: aide::openapi::ApiKeyLocation::Cookie,
            name: session_cookie,
            description: Some("The session cookie the browser flows set.".into()),
            extensions: Default::default(),
        },
    )];
    if bearer {
        out.push((
            "bearer".to_string(),
            SecurityScheme::Http {
                scheme: "bearer".into(),
                bearer_format: None,
                description: Some("The session token from the `X-Auth-Token` header.".into()),
                extensions: Default::default(),
            },
        ));
    }
    out
}

// --- Routing ---------------------------------------------------------------

/// aide's router takes the cookie layer exactly as axum's does, and keeps the
/// documentation it has collected.
impl<S> CookieLayered for aide::axum::ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn apply_cookie_layer<F, Fut>(self, middleware: F) -> Self
    where
        F: FnMut(Request, Next) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = HandlerResponse> + Send + 'static,
    {
        self.layer(from_fn(middleware))
    }
}
