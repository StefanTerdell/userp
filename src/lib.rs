#[cfg(feature = "email")]
mod email;
#[cfg(feature = "oauth")]
mod oauth;
#[cfg(feature = "password")]
mod password;

const SESSION_ID_KEY: &str = "auth:session_id";

#[cfg(feature = "email")]
pub use self::email::{EmailChallenge, EmailConfig, EmailPaths, EmailTrait, SmtpSettings};
#[cfg(feature = "oauth")]
pub use self::oauth::{
    providers, ClientRefreshResult, OAuthClients, OAuthConfig, OAuthPaths, OAuthToken,
    RefreshInitResult, UnmatchedOAuthToken,
};
#[cfg(feature = "password")]
pub use self::password::PasswordConfig;
#[cfg(all(feature = "password", feature = "email"))]
pub use self::password::PasswordReset;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Cookie, Expiration, Key, PrivateCookieJar, SameSite};
use std::{convert::Infallible, fmt::Display};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    PasswordReset { address: String },
    #[cfg(feature = "email")]
    Email { address: String },
    #[cfg(feature = "oauth")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    Never,
    OnSelf,
    OnEither,
}

pub trait UserTrait {
    fn get_id(&self) -> Uuid;

    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String>;
    #[cfg(feature = "password")]
    fn validate_password_hash(&self, password_hash: String) -> bool {
        self.get_password_hash()
            .is_some_and(|hash| password_hash == hash)
    }
}

#[async_trait]
pub trait AxumUserStore {
    type User: UserTrait;
    #[cfg(feature = "email")]
    type Email: EmailTrait;

    // session store
    async fn create_session(&self, session: LoginSession);
    async fn get_session(&self, session_id: Uuid) -> Option<LoginSession>;
    async fn delete_session(&self, session_id: Uuid);

    // user store
    async fn get_user(&self, user_id: Uuid) -> Option<Self::User>;

    // password user store
    #[cfg(feature = "password")]
    async fn get_user_by_password_id(&self, password_id: String) -> Option<Self::User>;
    #[cfg(feature = "password")]
    async fn create_password_user(&self, password_id: String, password_hash: String) -> Self::User;

    // email user store
    #[cfg(feature = "email")]
    async fn get_user_by_email(&self, email: String) -> Option<(Self::User, Self::Email)>;
    #[cfg(feature = "email")]
    async fn save_email_challenge(&self, challenge: EmailChallenge);
    #[cfg(feature = "email")]
    async fn consume_email_challenge(&self, code: String) -> Option<EmailChallenge>;
    #[cfg(feature = "email")]
    async fn set_user_email_verified(&self, user_id: Uuid, email: String);
    #[cfg(feature = "email")]
    async fn create_email_user(&self, email: String) -> (Self::User, Self::Email);

    // oauth token store
    #[cfg(feature = "oauth")]
    async fn get_user_by_oauth_provider_id(
        &self,
        provider_name: String,
        provider_user_id: String,
    ) -> Option<(Self::User, OAuthToken)>;
    #[cfg(feature = "oauth")]
    async fn create_or_update_oauth_token(&self, token: OAuthToken);
    #[cfg(feature = "oauth")]
    async fn create_oauth_user(
        &self,
        provider_name: String,
        token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, OAuthToken)>;
    #[cfg(feature = "oauth")]
    async fn get_user_oauth_token(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Option<(Self::User, OAuthToken)>;
}

pub struct AxumUser<S: AxumUserStore> {
    allow_signup: Allow,
    allow_login: Allow,
    jar: PrivateCookieJar,
    https_only: bool,
    store: S,
    #[cfg(feature = "password")]
    pass: PasswordConfig,
    #[cfg(feature = "email")]
    email: EmailConfig,
    #[cfg(feature = "oauth")]
    oauth: OAuthConfig,
}

impl<S: AxumUserStore> AxumUser<S> {
    async fn log_in(mut self, method: LoginMethod, user_id: Uuid) -> Self {
        let session_id = Uuid::new_v4();

        let session = LoginSession {
            id: session_id,
            user_id,
            method,
        };

        println!("Before create_session");

        self.store.create_session(session).await;

        println!("Before cookie add");

        self.jar = self.jar.add(
            Cookie::build((SESSION_ID_KEY, session_id.to_string()))
                .same_site(SameSite::Lax)
                .http_only(true)
                .expires(Expiration::Session)
                .secure(self.https_only)
                .path("/")
                .build(),
        );

        println!("After cookie add");

        self
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_out(mut self) -> Self {
        if let Some(session) = self.jar.get(SESSION_ID_KEY) {
            if let Ok(session_id) = Uuid::parse_str(session.value()) {
                self.store.delete_session(session_id).await;
                self.jar = self.jar.remove(SESSION_ID_KEY)
            }
        }

        self
    }

    fn session_id_cookie(&self) -> Option<Uuid> {
        let Some(session_id_cookie) = self.jar.get(SESSION_ID_KEY) else {
            println!("No session ID cookie found");
            return None;
        };

        let Ok(session_id) = Uuid::parse_str(session_id_cookie.value()) else {
            println!("Session ID not a UUID");
            return None;
        };

        Some(session_id)
    }

    fn is_login_session(#[allow(unused)] session: &LoginSession) -> bool {
        #[cfg(all(feature = "password", feature = "email"))]
        return !matches!(session.method, LoginMethod::PasswordReset { address: _ });

        #[cfg(not(all(feature = "password", feature = "email")))]
        return true;
    }

    pub async fn logged_in(&self) -> bool {
        self.session().await.is_some()
    }

    pub async fn session(&self) -> Option<LoginSession> {
        let session_id = self.session_id_cookie()?;
        println!("Finding session by id: {session_id:#?}");
        self.store
            .get_session(session_id)
            .await
            .filter(Self::is_login_session)
    }

    pub async fn user_session(&self) -> Option<(S::User, LoginSession)> {
        let session = self.session().await?;
        println!("Finding user by id: {:#?}", session.user_id);
        self.store
            .get_user(session.user_id)
            .await
            .map(|user| (user, session))
    }

    pub async fn user(&self) -> Option<S::User> {
        self.user_session().await.map(|(user, _)| user)
    }
}

impl<S: AxumUserStore> IntoResponseParts for AxumUser<S> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

#[derive(Clone)]
pub struct AxumUserConfig {
    pub key: Key,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub https_only: bool,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
}

impl AxumUserConfig {
    pub fn new(
        key: Key,
        #[cfg(feature = "password")] pass: PasswordConfig,
        #[cfg(feature = "email")] email: EmailConfig,
        #[cfg(feature = "oauth")] oauth: OAuthConfig,
    ) -> Self {
        Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnEither,
            #[cfg(feature = "password")]
            pass,
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "oauth")]
            oauth,
        }
    }

    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = allow_login;
        self
    }
}

#[async_trait]
impl<S, St> FromRequestParts<S> for AxumUser<St>
where
    St: AxumUserStore,
    AxumUserConfig: FromRef<S>,
    S: Send + Sync,
    St: AxumUserStore + FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = AxumUserConfig::from_ref(state);
        let jar = PrivateCookieJar::from_headers(&parts.headers, config.key);
        let store = St::from_ref(state);

        return Ok(AxumUser {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            https_only: config.https_only,
            jar,
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
