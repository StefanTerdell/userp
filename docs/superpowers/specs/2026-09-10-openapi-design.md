# OpenAPI support for authery

Status: implemented on branch `authery`, 2026-09-10.

## Goal

An app that mounts `auth.router()` can publish an OpenAPI document that
describes every route authery mounted, at the configured paths, with the
request bodies, query parameters, responses and security schemes those
routes really use. The document must not drift from the code, must work with
whichever OpenAPI library the app already uses, and must cost nothing to
apps that do not want it.

## Non-goals

- Shipping a docs UI. Apps pick Swagger UI, Scalar or Redoc themselves.
- Documenting the app's own routes. Authery only describes what it mounts.
- A utoipa-specific cargo feature. The neutral document round-trips into
  utoipa's types through serde, and that is documented as the utoipa path.
  A sugar feature can follow if users ask for one.
- Supporting aide 0.15 or older. Aide 0.16 (schemars 1) is the target.

## Decisions already made

| Question | Decision | Why |
|---|---|---|
| Schema source | `schemars` derives on the request and response types | Hand-written schemas drift from the structs; a derive cannot |
| Document types | Authery's own small serde structs for the OpenAPI wrapper | The subset authery emits is about 150 lines; no third-party type in the public API means no forced breaking change when utoipa or aide bump majors |
| Route table | One `Endpoint` enum drives both `router()` and `openapi()` | Two exhaustive `match`es make it impossible to mount an undocumented route or document an unmounted one |
| Schema dialect | Caller-selectable `SchemaSettings`, default draft 2020-12 labelled `3.1.0` | OpenAPI 3.1 schemas are JSON Schema 2020-12; utoipa 5 only deserializes `3.1.0` |
| Aide integration | Native: `api_router()` returns an `ApiRouter` | Aide owns the schema generator, so authery's types only need `JsonSchema` |
| Bodies | Already form or JSON via `FormOrJson` (commit 603bc73) | The document can honestly list both media types |
| Store errors | A `StoreError` trait replaces the `IntoResponse` requirement; nothing is exposed unless the store opts in with a `PublicError { status, message }` | The store error is an app-defined type that may carry anything; exposure must be deliberate, and a message matches how every other authery error reaches the client |
| Pages in the document | Excluded by default, `OpenApiOptions::with_pages(true)` includes them | The document's audience is API clients and SDK generators; HTML pages are noise to both |

## Usage

### No OpenAPI (unchanged)

```rust
let routes = Routes::default().with_prefix("/auth");
let auth = AutheryConfig::new(key, routes, PasswordConfig::new())?;

let app = Router::new()
    .route("/", get(index))
    .merge(auth.router::<MemoryStore, AppState>())
    .with_state(AppState { store, auth });
```

### Neutral document, served as JSON (`features = ["openapi"]`)

```rust
let auth = AutheryConfig::new(...)?.with_bearer_auth(true);
let doc = Arc::new(auth.openapi());

let app = Router::new()
    .route("/openapi.json", get(move || async move { Json(doc.to_json()) }))
    .merge(auth.router::<MemoryStore, AppState>())
    .with_state(AppState { store, auth });
```

`auth.openapi()` documents the API routes with draft 2020-12 schemas and
labels the document `3.1.0`. `openapi_with` takes options for everything
else:

```rust
use authery::openapi::OpenApiOptions;
use schemars::generate::SchemaSettings;

let doc = auth.openapi_with(
    OpenApiOptions::default()
        .with_pages(true)                                  // include the HTML page routes
        .with_schema_settings(SchemaSettings::openapi3()), // `nullable`, labelled 3.0.3
);
```

### With utoipa (`features = ["openapi"]`, no extra authery feature)

```rust
#[derive(OpenApi)]
#[openapi(info(title = "My API"), paths(list_widgets))]
struct ApiDoc;

let auth = AutheryConfig::new(...)?.with_bearer_auth(true);

let mut doc = ApiDoc::openapi();
doc.merge(auth.openapi().convert::<utoipa::openapi::OpenApi>()?);

let (router, doc) = OpenApiRouter::with_openapi(doc)
    .routes(routes!(list_widgets))
    .merge(OpenApiRouter::from(auth.router::<MemoryStore, AppState>()))
    .split_for_parts();

let app = router
    .merge(SwaggerUi::new("/docs").url("/openapi.json", doc))
    .with_state(AppState { store, auth });
```

`convert` is `serde_json::to_value` followed by `from_value`; it works for
any OpenAPI type that deserializes 3.1 documents.

### With aide (`features = ["aide"]`)

```rust
let auth = AutheryConfig::new(...)?.with_bearer_auth(true);

let mut api = OpenApi {
    info: Info { title: "My API".into(), ..Default::default() },
    ..Default::default()
};

let app = ApiRouter::new()
    .api_route("/widgets", get_with(list_widgets, |op| op.summary("List widgets")))
    .route("/openapi.json", get(serve_docs))
    .merge(auth.api_router::<MemoryStore, AppState>())
    .finish_api(&mut api)
    .layer(Extension(Arc::new(api)))
    .with_state(AppState { store, auth });
```

Authery's routes are registered through aide's typed routing, so
`finish_api` documents them alongside the app's own. Schemas land in the
app's `components` through aide's generator, so authery's and the app's
types share one dialect and one definitions table.

## Cargo features and dependencies

| Feature | Implies | Adds | Purpose |
|---|---|---|---|
| `openapi` | `axum` | `schemars = "1"` (public dependency) | `JsonSchema` derives, `openapi()` / `openapi_with()`, the `authery::openapi` module |
| `aide` | `openapi` | `aide = "0.16"` with `axum` (public dependency) | `OperationInput` / `OperationOutput` impls, `api_router()` |

Dev-dependencies only: `utoipa` with `default-features = false` and `aide`,
used by the round-trip tests. Users never pay for them.

`openapi` implies `axum` because the request and response types it
documents live in the axum layer and the document describes the axum
router. A future non-axum integration would move those types out; that is
not worth doing speculatively.

## Architecture

### The `Endpoint` enum

New file `src/axum/router/endpoint.rs`. One variant per mounted
(method, path) pair, cfg-gated exactly like today's `router()` body:

```rust
pub(crate) enum Endpoint {
    Logout,
    VerifySession,
    #[cfg(feature = "password")]
    LoginPassword,
    #[cfg(feature = "password")]
    SignupPassword,
    #[cfg(all(feature = "email", feature = "pages"))]
    LoginOtpPage,        // GET on the same path as LoginOtp
    #[cfg(feature = "email")]
    LoginOtp,            // POST
    // ...
}
```

Four functions, each an exhaustive `match`:

- `Endpoint::all() -> Vec<Endpoint>` lists the variants active under the
  current features. It is the only hand-maintained list, and a variant
  missing from it would be missing from both the router and the document,
  which the flow tests catch immediately.
- `path(&self, routes: &Routes<String>) -> &str` and `method(&self) -> Method`.
- `handler<St, S>(&self) -> MethodRouter<S>` returns today's handler wrapped
  in `get(...)` or `post(...)`.
- `describe(&self, ctx: &mut Describe) -> Operation` (cfg `openapi`) returns
  the operation document. `Describe` wraps the schemars `SchemaGenerator`
  plus the bits of config the document needs.

`AxumRouter::router()` becomes a fold over `Endpoint::all()`: for each
endpoint, `router.route(path, handler)`. Axum merges method routers that
share a path, so GET and POST variants on one path stay separate variants.

Operation ids are the variant names in snake case, for example
`login_password`. Tags follow the router module: Session, Pages, User,
Password, Email, OAuth, Passkeys, MFA, SMS.

### Store errors

Today the axum layer requires `St::Error: IntoResponse`, so what a store
failure reveals to the client is decided by the app's `IntoResponse` impl
with nothing steering it toward safety. The store error is an app-defined
type and may carry connection strings, SQL or worse. This changes to an
opt-in contract in `src/store.rs`:

```rust
/// Implemented by the store's error type. Nothing is exposed unless you say so.
pub trait StoreError: std::error::Error + Send + Sync + 'static {
    /// What of this error may reach the client. Default: nothing.
    fn public(&self) -> Option<PublicError> {
        None
    }
}

/// A client-facing rendering of a store error: a status and a message.
pub struct PublicError {
    status: u16,
    message: String,
}

impl PublicError {
    pub fn new(status: u16, message: impl Display) -> Self;
}
```

A message, not a schema, because that is how every other authery error
reaches the client: flow errors are `Display` strings that ride `?error=`
for browsers and become `{ "error": … }` for JSON clients. Store errors
follow the same path. The trait has no required items, so the safe default
costs implementors an empty `impl StoreError for MyError {}`, which
replaces today's `impl IntoResponse`. Both example stores change
accordingly.

Every handler bound `St::Error: IntoResponse` becomes
`St::Error: StoreError`, and authery renders store failures itself in one
place, using the same `Accept` check the transport layer already uses:

| Client | `public()` is `Some(p)` | `public()` is `None` |
|---|---|---|
| JSON | `p.status` with `ApiError { error: p.message }` | `500` with `ApiError { error: "Internal server error" }` |
| Browser, `pages` on | `Pages::error(status, message)` | `Pages::error(500, "Something went wrong")` |
| Browser, `pages` off | plain text, `p.status` | plain text, `500` |

The real error is logged through tracing at error level in every case.
`Pages` gains an `error` method with a default implementation rendering a
built-in template in the style of the paused page, so custom page sets
keep compiling. A status outside `400..=599` is rendered as `500`.

### Request and response types

Every request struct in `src/axum/router/*.rs` gets
`#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]`. Field doc
comments become schema descriptions, so field documentation lives in one
place. No struct changes shape.

The JSON flow responses become real types in `src/axum/response.rs`,
replacing the ad hoc `serde_json::Map` in the redirect translator and the
`json!` in `json_error`:

```rust
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct FlowResult { pub next: String, pub message: Option<String> }

// same derives
pub struct FlowError  { pub error: String, pub next: String }
pub struct ApiError   { pub error: String }
```

The runtime body and the documented body are then the same type.

Handlers change their return type from `Result<impl IntoResponse, St::Error>`
to `Result<Response, St::Error>`. Most already call `into_response()` on
every arm; the rest are mechanical. This is required for the aide
integration, which cannot see through `impl IntoResponse`, and it costs
nothing elsewhere.

Webauthn payloads come from `webauthn-rs-proto`, which does not implement
`JsonSchema`. They are documented as `type: object` with a description and
an `externalDocs` link to the W3C credential types.

### Response sets

Each endpoint picks one of a few response sets, so the document stays
consistent and the table stays short:

| Set | Used by | Responses |
|---|---|---|
| Flow | Every form-driven flow POST | `303` redirect for browsers; `200 FlowResult` and `422 FlowError` under `Accept: application/json` |
| Page | Pages GET routes | `200 text/html` |
| Json(T) | Webauthn ceremonies, TOTP enrol | `200 T`, `400 ApiError`, `401 ApiError` as applicable |
| Status | `verify_session` | `200` or `401`, empty |
| Redirect | OAuth callback, email link GETs | `303` |

Every set on an endpoint that touches the store also lists `500 ApiError`
and a `4XX ApiError`, the latter being what a store's `PublicError` renders
to. The wildcard key is used because the status is chosen per value.

When bearer auth is on, every response set that can establish a session
gains the `X-Auth-Token` response header on its success responses.

### Security schemes

`components.securitySchemes` always contains `session_cookie`, an
`apiKey` in `cookie` named after the configured session cookie. With
`bearer_auth` it also contains `bearer`, an `http` scheme of type `bearer`.
User-scoped endpoints (everything under `user`, logout, verify_session, the
MFA second-factor POSTs) list both as alternatives. Public flow endpoints
list none.

### Query parameters

Query structs are documented as one parameter per field. A small generic
walks the root object schema schemars produces for `T`, emitting
`{ name, in: query, required, schema, description }` per property. This is
what utoipa's `IntoParams` does internally; here it is one function.

### The document

`src/openapi.rs` holds the serde structs: `Document`, `Info`, `PathItem`,
`Operation`, `Parameter`, `RequestBody`, `MediaType`, `Response`, `Header`,
`Components`, `SecurityScheme`, and `Schema` as a `serde_json::Value`
newtype since schemars already produced it. Maps are `BTreeMap` so output
is deterministic without a new dependency. `Info` is
`{ title: "Authery", version: <crate version> }`; consumers that merge keep
their own.

```rust
impl Document {
    pub fn to_json(&self) -> serde_json::Value;
    pub fn convert<T: DeserializeOwned>(&self) -> serde_json::Result<T>;
}

#[derive(Default)]
pub struct OpenApiOptions { /* pages: bool, schema_settings: SchemaSettings */ }

impl OpenApiOptions {
    pub fn with_pages(self, include: bool) -> Self;            // default false
    pub fn with_schema_settings(self, settings: SchemaSettings) -> Self; // default draft2020_12
}

pub trait AxumRouter {
    // ...existing router() and config accessors...
    #[cfg(feature = "openapi")]
    fn openapi(&self) -> Document;                              // OpenApiOptions::default()
    #[cfg(feature = "openapi")]
    fn openapi_with(&self, options: OpenApiOptions) -> Document;
}
```

`openapi_with` overrides only the settings' `definitions_path` to
`#/components/schemas/`, then hands the generator to `Describe`. It walks
`Endpoint::all()`, skipping endpoints whose response set is Page unless
`with_pages(true)`, then drains the generator's definitions into
`components.schemas`. The version label is `3.0.3` when the settings'
meta-schema is the OpenAPI 3.0 one, else `3.1.0`.

### Aide (`feature = "aide"`)

In `src/axum/aide.rs`:

- `impl<T: JsonSchema> OperationInput for FormOrJson<T>` declares a request
  body with both `application/x-www-form-urlencoded` and `application/json`
  media types sharing one schema, mirroring aide's own `Form<T>` impl.
- `impl<St> OperationInput for AxumAuthery<St>` is a no-op, like aide's
  cookie jar impls. Security requirements come from the endpoint table.
- `OperationOutput` for `FlowResult`, `FlowError`, `ApiError`, and for
  authery's store-error response type. Because authery renders store errors
  itself, nothing is required of the app's error type beyond `StoreError`.
- `AxumRouter::api_router<St, S>() -> ApiRouter<S>` folds `Endpoint::all()`
  using aide's `get_with` / `post_with`, applying each endpoint's response
  set and security through `TransformOperation`.

## Testing

- `tests/openapi.rs` (feature `openapi`, all features in CI):
  - **Round trip.** `auth.openapi().convert::<utoipa::openapi::OpenApi>()`
    and `convert::<aide::openapi::OpenApi>()` both succeed and keep every
    path and every component schema. This is the guard that the hand-rolled
    wrapper and schemars' output are what those libraries accept.
  - **Path drift.** For every documented (method, path), the real router
    answers anything but `404` or `405` to a bodiless request. Combined
    with the exhaustive `match`es this closes the loop in both directions.
  - **Snapshot.** The default-feature document is compared to
    `tests/snapshots/openapi.json`; `UPDATE_SNAPSHOTS=1` rewrites it. No
    snapshot crate.
  - **Dialect.** `openapi_with(SchemaSettings::openapi3())` labels `3.0.3`
    and spells `Option<String>` with `nullable`.
- `tests/aide.rs` (feature `aide`): `api_router()` finished through
  `finish_api` yields the same path set as `openapi()`.
- `tests/axum_router.rs`: a store error with the default `public()` yields
  `500 {"error": "Internal server error"}` for JSON clients and the error
  page for browsers, and never the error's `Display` text; a store returning
  `PublicError::new(409, ...)` yields `409` with that message in both modes.
- `tests/openapi.rs` also checks that `openapi()` contains no Page
  operations and `openapi_with(OpenApiOptions::default().with_pages(true))`
  contains every one.
- Existing flow and transport tests guard the `router()` rewrite, which
  must not change behaviour.
- Optional: `dev/e2e` lints the served document with a Redocly or
  Spectral run against the `full` example.

## Delivery order

1. `StoreError` / `PublicError`; handler bounds switched; store failures
   rendered by authery, with the new `Pages::error` template; example stores
   updated; transport tests for both exposure modes.
2. `Endpoint` enum and `router()` rewritten as a fold over it. No behaviour
   change; all existing tests pass unchanged.
3. Handlers return `Response`; `FlowResult`, `FlowError`, `ApiError` used at
   runtime. Transport tests extended to assert the exact JSON shapes.
4. `openapi` feature: derives, document types, `describe`, `openapi()` /
   `openapi_with()`, round-trip and drift tests, snapshot.
5. `aide` feature and its test.
6. README sections "OpenAPI" and the store chapter's error contract,
   CHANGELOG entry, CI matrix entries for `openapi` and `aide`.

Each step is a commit that builds and passes on its own.

## Resolved in review

- Store errors are never exposed unless the store returns a `PublicError`,
  and what is exposed is a message rendered through the same JSON-or-page
  switch as every other error. The aide feature therefore asks nothing of
  the app's error type, and the document does not depend on the store type.
- Pages GET routes are excluded by default and included with
  `OpenApiOptions::with_pages(true)`.
- `openapi()` lives on `AxumRouter` beside `router()`.
- Browser users hitting a store outage see the new error page instead of
  whatever the app's former `IntoResponse` impl produced.
