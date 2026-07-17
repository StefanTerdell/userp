#[cfg(feature = "email")]
use crate::email::EmailConfig;
#[cfg(feature = "oauth")]
use crate::oauth::OAuthConfig;
#[cfg(feature = "password")]
use crate::password::PasswordConfig;
use crate::{
    constants::SESSION_ID_KEY,
    models::{AutheryCookies, LoginSession},
    store::AutheryStore,
};
use crate::{
    models::{Allow, LoginMethod},
    routes::Routes,
};
use chrono::{Duration, Utc};

#[derive(Debug, Clone)]
pub struct CoreAuthery<S: AutheryStore, C: AutheryCookies> {
    pub routes: Routes<String>,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub session_lifetime: Duration,
    pub max_concurrent_sessions: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub rate_limiter: std::sync::Arc<dyn crate::ratelimit::RateLimiter>,
    /// Receives auth events; see [`crate::events`].
    pub events: std::sync::Arc<dyn crate::events::AuthEventHandler>,
    /// A bearer token presented by the client (the transport layer populates
    /// this from the Authorization header when bearer auth is enabled). When
    /// present it takes precedence over the session cookie.
    pub bearer_token: Option<String>,
    pub cookies: C,
    pub store: S,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
    #[cfg(feature = "webauthn")]
    pub webauthn: crate::webauthn::WebauthnConfig,
    #[cfg(feature = "totp")]
    pub totp: crate::totp::TotpConfig,
    #[cfg(feature = "sms")]
    pub sms: crate::sms::SmsConfig,
    #[cfg(feature = "mfa")]
    pub mfa_policy: crate::mfa::MfaPolicy,
    #[cfg(feature = "pages")]
    pub pages: std::sync::Arc<dyn crate::pages::Pages>,
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Hand an event to the registered handler; see [`crate::events`].
    pub(crate) fn emit(&self, event: crate::events::AuthEvent) {
        self.events.on_event(event);
    }

    /// Consult the rate limiter and emit an event when it blocks.
    pub(crate) async fn check_rate(
        &self,
        op: crate::ratelimit::RateLimitOp<'_>,
    ) -> Result<(), crate::ratelimit::RateLimited> {
        use crate::ratelimit::RateLimitOp;

        #[allow(unreachable_patterns)]
        let (operation, identifier): (&'static str, String) = match &op {
            #[cfg(feature = "password")]
            RateLimitOp::PasswordAttempt { password_id } => {
                ("password_attempt", password_id.to_string())
            }
            #[cfg(feature = "email")]
            RateLimitOp::EmailSend { address } => ("email_send", address.to_string()),
            #[cfg(feature = "email")]
            RateLimitOp::OtpAttempt { address } => ("otp_attempt", address.to_string()),
            #[cfg(feature = "totp")]
            RateLimitOp::TotpAttempt { user_id } => ("totp_attempt", user_id.to_string()),
            #[cfg(feature = "mfa")]
            RateLimitOp::RecoveryAttempt { user_id } => ("recovery_attempt", user_id.to_string()),
            #[cfg(feature = "sms")]
            RateLimitOp::SmsSend { number } => ("sms_send", number.to_string()),
            #[cfg(feature = "sms")]
            RateLimitOp::SmsAttempt { number } => ("sms_attempt", number.to_string()),
            _ => ("other", String::new()),
        };

        let result = self.rate_limiter.check(op).await;

        if result.is_err() {
            self.emit(crate::events::AuthEvent::RateLimited {
                operation,
                identifier,
            });
        }

        result
    }

    /// Create a login session for the user. The built-in flows call this
    /// after verifying their credentials; it is public so apps with custom
    /// authentication methods can mint sessions through the same path
    /// (MFA policy, private-org provisioning and the session cap all apply).
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_in(
        mut self,
        method: LoginMethod,
        user_id: &S::UserId,
    ) -> Result<Self, S::Error> {
        // When the MFA policy demands a second factor for this method and the
        // user has one registered, downgrade to a pending session that can
        // only complete the MFA flow.
        #[cfg(feature = "mfa")]
        let method = self.mfa_wrap_method(method, user_id).await?;

        let expires = Utc::now() + self.session_lifetime;
        let session = self.store.create_session(user_id, method, expires).await?;

        self.emit(crate::events::AuthEvent::LoginSucceeded {
            user_id: user_id.to_string(),
            method: session.get_method(),
        });

        if let Some(max) = self.max_concurrent_sessions {
            self.enforce_session_cap(user_id, max).await?;
        }

        self.cookies
            .add(SESSION_ID_KEY, &session.get_id().to_string());

        Ok(self)
    }

    /// Delete the user's oldest sessions until at most `max` remain. Expired
    /// sessions are already logged-out, so they are evicted first regardless of
    /// the cap. "Oldest" is by earliest expiry, which matches creation order
    /// since every session gets the same lifetime.
    async fn enforce_session_cap(&self, user_id: &S::UserId, max: usize) -> Result<(), S::Error> {
        let mut sessions = self.store.get_user_sessions(user_id).await?;

        sessions.sort_by_key(|s| s.get_expires());

        let (expired, live): (Vec<_>, Vec<_>) = sessions.into_iter().partition(|s| s.is_expired());

        let excess = live.len().saturating_sub(max);

        for session in expired.iter().chain(live.iter().take(excess)) {
            self.store
                .delete_session(user_id, &session.get_id())
                .await?;
        }

        Ok(())
    }

    pub fn get_encoded_cookies(&self) -> Vec<String> {
        self.cookies.list_encoded()
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_out(mut self) -> Result<Self, S::Error> {
        if let Some(session_id) = self.session_id_cookie() {
            self.cookies.remove(SESSION_ID_KEY);

            // Delete whatever session the cookie points at - including
            // password reset sessions, which session() filters out.
            if let Some(session) = self.store.get_session(&session_id).await? {
                self.store
                    .delete_session(&session.get_user_id(), &session.get_id())
                    .await?;
            }
        } else if self.cookies.get(SESSION_ID_KEY).is_some() {
            self.cookies.remove(SESSION_ID_KEY);
        }

        Ok(self)
    }

    pub(crate) fn session_id_cookie(&self) -> Option<S::SessionId> {
        // An explicit bearer token wins over the cookie and never falls back,
        // so a bad token can't silently ride an unrelated browser session.
        if let Some(token) = &self.bearer_token {
            return token.parse::<S::SessionId>().ok();
        }

        let session_id_cookie = self.cookies.get(SESSION_ID_KEY)?;

        session_id_cookie.parse::<S::SessionId>().ok()
    }

    /// Whether this session counts as logged-in. Purpose-bound sessions
    /// (password reset, pending MFA) can only drive their own flow.
    fn is_login_session(session: &S::LoginSession) -> bool {
        match session.get_method() {
            #[cfg(all(feature = "password", feature = "email"))]
            LoginMethod::PasswordReset { .. } => false,
            #[cfg(feature = "mfa")]
            LoginMethod::MfaPending { .. } => false,
            _ => true,
        }
    }

    pub async fn logged_in(&self) -> Result<bool, S::Error> {
        Ok(self.session().await?.is_some())
    }

    pub async fn session(&self) -> Result<Option<S::LoginSession>, S::Error> {
        let Some(session_id) = self.session_id_cookie() else {
            return Ok(None);
        };

        let Some(session) = self.store.get_session(&session_id).await? else {
            return Ok(None);
        };

        // An expired session counts as logged-out; evict it from the store.
        if session.is_expired() {
            self.store
                .delete_session(&session.get_user_id(), &session.get_id())
                .await?;
            return Ok(None);
        }

        // The idle timeout works the same way, when the store tracks
        // activity. Touches are throttled to once a minute.
        if let Some(idle_timeout) = self.idle_timeout
            && let Some(last_seen) = session.get_last_seen()
        {
            let now = Utc::now();
            if now - last_seen > idle_timeout {
                self.store
                    .delete_session(&session.get_user_id(), &session.get_id())
                    .await?;
                return Ok(None);
            }
            if now - last_seen > Duration::seconds(60) {
                self.store
                    .touch_session(&session.get_user_id(), &session.get_id(), now)
                    .await?;
            }
        }

        Ok(Some(session).filter(Self::is_login_session))
    }

    pub async fn user_session(&self) -> Result<Option<(S::User, S::LoginSession)>, S::Error> {
        let Some(session) = self.session().await? else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_user(&session.get_user_id())
            .await?
            .map(|user| (user, session)))
    }

    pub async fn user(&self) -> Result<Option<S::User>, S::Error> {
        Ok(self.user_session().await?.map(|(user, _)| user))
    }
}
