#[cfg(feature = "email")]
use crate::email::EmailConfig;
#[cfg(feature = "oauth-callbacks")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "password")]
use crate::password::PasswordConfig;
use crate::{
    constants::SESSION_ID_KEY,
    models::{LoginSession, UserpCookies},
    store::UserpStore,
};
use userp_client::{
    models::{Allow, LoginMethod},
    routes::Routes,
};

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CoreUserp<S: UserpStore, C: UserpCookies> {
    pub routes: Routes<String>,
    pub(crate) allow_signup: Allow,
    pub(crate) allow_login: Allow,
    pub(crate) cookies: C,
    pub(crate) store: S,
    #[cfg(feature = "password")]
    pub(crate) pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub(crate) email: EmailConfig,
    #[cfg(feature = "oauth-callbacks")]
    pub(crate) oauth: OAuthConfig,
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    pub(crate) async fn log_in(
        mut self,
        method: LoginMethod,
        user_id: Uuid,
    ) -> Result<Self, S::Error> {
        let session = self.store.create_session(user_id, method).await?;

        self.cookies
            .add(SESSION_ID_KEY, &session.get_id().to_string());

        Ok(self)
    }

    pub fn get_encoded_cookies(&self) -> Vec<String> {
        self.cookies.list_encoded()
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_out(mut self) -> Result<Self, S::Error> {
        if self.cookies.get(SESSION_ID_KEY).is_some() {
            let session = self.session().await;

            self.cookies.remove(SESSION_ID_KEY);

            if let Some(session) = session? {
                self.store
                    .delete_session(session.get_user_id(), session.get_id())
                    .await?;
            }
        }

        Ok(self)
    }

    pub(crate) fn session_id_cookie(&self) -> Option<Uuid> {
        let session_id_cookie = self.cookies.get(SESSION_ID_KEY)?;

        let session_id = Uuid::parse_str(&session_id_cookie).ok()?;

        Some(session_id)
    }

    fn is_login_session(session: &S::LoginSession) -> bool {
        #[cfg(all(feature = "password", feature = "email"))]
        return !matches!(
            session.get_method(),
            LoginMethod::PasswordReset { address: _ }
        );

        #[cfg(not(all(feature = "password", feature = "email")))]
        return true;
    }

    pub async fn logged_in(&self) -> Result<bool, S::Error> {
        Ok(self.session().await?.is_some())
    }

    pub async fn session(&self) -> Result<Option<S::LoginSession>, S::Error> {
        let Some(session_id) = self.session_id_cookie() else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_session(session_id)
            .await?
            .filter(Self::is_login_session))
    }

    pub async fn user_session(&self) -> Result<Option<(S::User, S::LoginSession)>, S::Error> {
        let Some(session) = self.session().await? else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_user(session.get_user_id())
            .await?
            .map(|user| (user, session)))
    }

    pub async fn user(&self) -> Result<Option<S::User>, S::Error> {
        Ok(self.user_session().await?.map(|(user, _)| user))
    }
}
