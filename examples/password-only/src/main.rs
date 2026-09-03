mod templates;

use self::templates::{IndexTemplate, ProtectedTemplate};

use askama::Template;
use axum::Form;
use axum::response::{Html, IntoResponse};
use axum::{Router, response::Redirect, routing::get, serve};
use axum_macros::FromRef;
use memory_store::MemoryStore;
use serde::Deserialize;

#[derive(Deserialize)]
struct SigninForm {
    email_address: String,
    password: String,
}
use templates::SigninTemplate;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use authery::prelude::*;

#[derive(Clone, FromRef)]
struct AppState {
    store: MemoryStore,
    auth: AutheryConfig,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let key = String::from(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );

    let auth = AutheryConfig::new(key, Routes::default(), PasswordConfig::new())
        .expect("valid auth config")
        .with_https_only(false)
        .with_allow_signup(Allow::OnEither)
        .with_allow_login(Allow::OnEither);

    let state = AppState {
        store: MemoryStore::default(),
        auth,
    };

    let app = Router::new()
        .route("/", get(get_index))
        .route("/signin", get(get_signin).post(post_signin))
        .route("/protected", get(get_protected))
        .route("/logout", get(get_logout))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    println!("Authery example listening at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index(auth: Authery<MemoryStore>) -> impl IntoResponse {
    let logged_in = auth.logged_in().await.unwrap();

    Html(IndexTemplate { logged_in }.render().unwrap())
}

async fn get_signin() -> impl IntoResponse {
    Html(SigninTemplate { message: None }.render().unwrap())
}

async fn post_signin(
    auth: Authery<MemoryStore>,
    Form(data): Form<SigninForm>,
) -> impl IntoResponse {
    match auth
        .password_login(&data.email_address, &data.password)
        .await
    {
        Ok(auth) => (auth, Redirect::to("/protected")).into_response(),
        Err(err) => Html(
            SigninTemplate {
                message: Some(err.to_string()),
            }
            .render()
            .unwrap(),
        )
        .into_response(),
    }
}

async fn get_protected(auth: Authery<MemoryStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await.unwrap() else {
        return Redirect::to("/signin").into_response();
    };

    Html(
        ProtectedTemplate {
            user: format!("{user:#?}"),
            session: format!("{session:#?}"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

async fn get_logout(auth: Authery<MemoryStore>) -> impl IntoResponse {
    let auth = auth.log_out().await.unwrap();

    (auth, Redirect::to("/"))
}
