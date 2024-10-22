mod models;
mod password;
mod store;
mod templates;

use self::store::MemoryStore;
use self::templates::{IndexTemplate, ProtectedTemplate};

use askama_axum::IntoResponse;
use axum::Form;
use axum::{extract::State, response::Redirect, routing::get, serve, Router};
use axum_macros::FromRef;
use models::SigninForm;
use templates::SigninTemplate;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use userp::{
    prelude::{Allow, PasswordConfig, Routes, UserpConfig},
    Userp,
};

#[derive(Clone, FromRef)]
struct AppState {
    store: MemoryStore,
    auth: UserpConfig,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let key = String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let auth = UserpConfig::new(key, Routes::default(), PasswordConfig::new())
        .with_https_only(false)
        .with_allow_signup(Allow::OnEither)
        .with_allow_login(Allow::OnEither);

    let state = AppState {
        store: MemoryStore::default(),
        auth,
    };

    let app = Router::new()
        .route("/store", get(get_store))
        .route("/", get(get_index))
        .route("/signin", get(get_signin).post(post_signin))
        .route("/protected", get(get_protected))
        .route("/logout", get(get_logout))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    println!("User example minimal axum/memstore running at http://localhost:3000 :)");
    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_index(auth: Userp<MemoryStore>) -> impl IntoResponse {
    let logged_in = auth.logged_in().await.unwrap();

    IndexTemplate { logged_in }
}

async fn get_signin() -> impl IntoResponse {
    SigninTemplate { message: None }
}

async fn post_signin(auth: Userp<MemoryStore>, Form(data): Form<SigninForm>) -> impl IntoResponse {
    match auth
        .password_login(&data.email_address, &data.password)
        .await
    {
        Ok(auth) => (auth, Redirect::to("/protected")).into_response(),
        Err(err) => SigninTemplate {
            message: Some(err.to_string()),
        }
        .into_response(),
    }
}

async fn get_store(State(state): State<AppState>) -> impl IntoResponse {
    format!("{:#?}", state.store).into_response()
}

async fn get_protected(auth: Userp<MemoryStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await.unwrap() else {
        return Redirect::to("/signin").into_response();
    };

    ProtectedTemplate {
        user: format!("{user:#?}"),
        session: format!("{session:#?}"),
    }
    .into_response()
}

async fn get_logout(auth: Userp<MemoryStore>) -> impl IntoResponse {
    auth.log_out().await.unwrap();

    Redirect::to("/")
}
