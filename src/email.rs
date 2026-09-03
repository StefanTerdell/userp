#[cfg(feature = "email")]
pub mod login;
#[cfg(feature = "email")]
pub mod otp;
#[cfg(all(feature = "email", feature = "password"))]
pub mod reset;
#[cfg(feature = "email")]
pub mod signup;
#[cfg(feature = "email")]
pub mod verify;

use chrono::Duration;
#[cfg(feature = "email")]
use chrono::Utc;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
};
use thiserror::Error;
use url::Url;
#[cfg(feature = "email")]
use uuid::Uuid;

use crate::models::Allow;
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, email::EmailChallenge},
    store::AutheryStore,
};

/// A composed email: subject + HTML body.
pub struct EmailContent {
    pub subject: String,
    pub html_body: String,
}

/// The copy for every email authery sends. Implement this to brand,
/// rephrase or localize the messages - each method has a sensible English
/// default, so override only what you need. Rendering is plain string
/// building; bring your own templating inside the methods if you like.
pub trait EmailMessages: Send + Sync + std::fmt::Debug {
    /// The magic-link login email; `url` completes the login.
    fn login_link(&self, url: &url::Url) -> EmailContent {
        EmailContent {
            subject: "Login link".into(),
            html_body: format!("<a href=\"{url}\">Click here to log in</a>"),
        }
    }

    /// The magic-link signup email.
    fn signup_link(&self, url: &url::Url) -> EmailContent {
        EmailContent {
            subject: "Sign-up link".into(),
            html_body: format!("<a href=\"{url}\">Click here to sign up</a>"),
        }
    }

    /// The address-verification email.
    fn verify_link(&self, url: &url::Url) -> EmailContent {
        EmailContent {
            subject: "Verify your email address".into(),
            html_body: format!("<a href=\"{url}\">Click here to verify email</a>"),
        }
    }

    /// The password-reset email.
    fn reset_link(&self, url: &url::Url) -> EmailContent {
        EmailContent {
            subject: "Reset your password".into(),
            html_body: format!("<a href=\"{url}\">Click here to reset password</a>"),
        }
    }

    /// The one-time login/signup code email (`otp`).
    #[cfg(feature = "email")]
    fn login_code(&self, code: &str) -> EmailContent {
        EmailContent {
            subject: "Your login code".into(),
            html_body: format!(
                "<p>Your login code is:</p><h1>{code}</h1><p>It expires shortly. If you did not request it, ignore this email.</p>"
            ),
        }
    }

    /// The MFA second-factor code email.
    #[cfg(all(feature = "email", feature = "mfa"))]
    fn mfa_code(&self, code: &str) -> EmailContent {
        EmailContent {
            subject: "Your verification code".into(),
            html_body: format!(
                "<p>Your verification code is:</p><h1>{code}</h1><p>It expires shortly. If you did not request it, ignore this email.</p>"
            ),
        }
    }
}

/// The built-in English copy - every [`EmailMessages`] default, unchanged.
#[derive(Debug, Clone, Copy)]
pub struct DefaultEmailMessages;

impl EmailMessages for DefaultEmailMessages {}

/// Which link email a challenge send composes; see [`EmailMessages`].
#[cfg(feature = "email")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum EmailLinkKind {
    LogIn,
    SignUp,
    Verify,
    Reset,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    /// Offer magic-link login/signup. Verification and password-reset links
    /// are unaffected. Defaults to `true`.
    pub offer_links: bool,
    /// Offer one-time-code login/signup (and the emailed MFA factor's UI).
    /// Defaults to `true`.
    pub offer_otp: bool,
    pub challenge_lifetime: Duration,
    pub base_url: Url,
    pub smtp: SmtpSettings,
    /// Generates the one-time codes for the `otp` flows (and the emailed MFA
    /// factor). Defaults to six digits; see [`crate::codes`].
    #[cfg(feature = "email")]
    pub code_generator: std::sync::Arc<dyn crate::codes::CodeGenerator>,
    /// Composes the emails authery sends; see [`EmailMessages`].
    pub messages: std::sync::Arc<dyn EmailMessages>,
}

impl EmailConfig {
    pub fn new(base_url: Url, smtp: SmtpSettings) -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            offer_links: true,
            offer_otp: true,
            challenge_lifetime: Duration::minutes(5),
            base_url,
            smtp,
            #[cfg(feature = "email")]
            code_generator: std::sync::Arc::new(crate::codes::NumericCode::default()),
            messages: std::sync::Arc::new(DefaultEmailMessages),
        }
    }

    /// Offer or withhold magic-link login/signup; see
    /// [`EmailConfig::offer_links`].
    pub fn with_links(mut self, offer_links: bool) -> Self {
        self.offer_links = offer_links;
        self
    }

    /// Offer or withhold one-time-code login/signup; see
    /// [`EmailConfig::offer_otp`].
    pub fn with_otp(mut self, offer_otp: bool) -> Self {
        self.offer_otp = offer_otp;
        self
    }

    /// Replace the email copy; see [`EmailMessages`].
    pub fn with_messages(mut self, messages: impl EmailMessages + 'static) -> Self {
        self.messages = std::sync::Arc::new(messages);
        self
    }

    /// Replace the one-time-code generator; see [`crate::codes`].
    #[cfg(feature = "email")]
    pub fn with_code_generator(
        mut self,
        code_generator: impl crate::codes::CodeGenerator + 'static,
    ) -> Self {
        self.code_generator = std::sync::Arc::new(code_generator);
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_challenge_lifetime(mut self, challenge_lifetime: Duration) -> Self {
        self.challenge_lifetime = challenge_lifetime;
        self
    }
}

/// SMTP connection settings. The server is given as an SMTP URL (parsed by
/// lettre), which encodes host, port, credentials and TLS mode in one string:
///
/// - `smtps://user:pass@smtp.example.com:465` - implicit TLS
/// - `smtp://user:pass@smtp.example.com:587?tls=required` - STARTTLS
/// - `smtp://localhost:1025` - plain, for local dev catchers like Mailhog
///
/// Percent-encode reserved characters in the credentials.
#[derive(Debug, Clone)]
pub struct SmtpSettings {
    pub server_url: String,
    pub from: String,
}

impl SmtpSettings {
    pub fn new(server_url: impl Into<String>, from: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            from: from.into(),
        }
    }
}

/// Delivery variants display a generic message; the cause is in `source()`
/// and in [`AuthEvent::DeliveryFailed`](crate::events::AuthEvent::DeliveryFailed).
#[derive(Debug, Error)]
pub enum SendEmailChallengeError<StoreError: std::error::Error> {
    #[error(transparent)]
    RateLimited(crate::ratelimit::RateLimited),
    #[error("Could not build the email link")]
    Url(#[source] url::ParseError),
    #[error("Invalid email address")]
    Address(#[source] lettre::address::AddressError),
    #[error("Could not send the email, please try again later")]
    MessageBuilding(#[source] lettre::error::Error),
    #[error("Could not send the email, please try again later")]
    Transport(#[source] lettre::transport::smtp::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

crate::ratelimit::impl_maybe_rate_limited!(SendEmailChallengeError, RateLimited);

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    #[cfg(feature = "email")]
    async fn send_email_challenge(
        &self,
        path: String,
        address: String,
        kind: EmailLinkKind,
        next: Option<String>,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        self.check_rate(crate::ratelimit::RateLimitOp::EmailSend { address: &address })
            .await
            .map_err(SendEmailChallengeError::RateLimited)?;

        let code = Uuid::new_v4().to_string().replace('-', "");

        let challenge = self
            .store
            .create_challenge(
                address,
                code,
                next,
                Utc::now() + self.email.challenge_lifetime,
            )
            .await?;

        let code = challenge.get_code();

        let url = self
            .email
            .base_url
            .join(&format!("{path}?code={code}"))
            .map_err(SendEmailChallengeError::Url)?;

        let content = match kind {
            EmailLinkKind::LogIn => self.email.messages.login_link(&url),
            EmailLinkKind::SignUp => self.email.messages.signup_link(&url),
            EmailLinkKind::Verify => self.email.messages.verify_link(&url),
            EmailLinkKind::Reset => self.email.messages.reset_link(&url),
        };

        self.send_email(challenge.get_address(), &content.subject, content.html_body)
            .await
    }

    pub(crate) async fn send_email(
        &self,
        to: &str,
        subject: &str,
        html_body: String,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        let result = self.send_email_inner(to, subject, html_body).await;

        if let Err(err) = &result {
            self.emit(crate::events::AuthEvent::DeliveryFailed {
                channel: crate::events::DeliveryChannel::Email,
                recipient: to.to_string(),
                error: format!("{err}: {}", crate::events::source_chain(err)),
            });
        }

        result
    }

    async fn send_email_inner(
        &self,
        to: &str,
        subject: &str,
        html_body: String,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        let email = Message::builder()
            .from(
                self.email
                    .smtp
                    .from
                    .parse()
                    .map_err(SendEmailChallengeError::Address)?,
            )
            .to(to.parse().map_err(SendEmailChallengeError::Address)?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body)
            .map_err(SendEmailChallengeError::MessageBuilding)?;

        let mailer =
            AsyncSmtpTransport::<Tokio1Executor>::from_url(self.email.smtp.server_url.as_str())
                .map_err(SendEmailChallengeError::Transport)?
                .build();

        mailer
            .send(email)
            .await
            .map_err(SendEmailChallengeError::Transport)?;

        Ok(())
    }
}

/// Consume-or-expiry failure for an emailed challenge.
#[derive(Debug, Error)]
pub enum EmailChallengeError<StoreError: std::error::Error> {
    #[error("Challenge expired")]
    Expired { address: String },
    #[error("Challenge not found")]
    NotFound,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailLinkInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("{0} not allowed")]
    NotAllowed(crate::models::Intent),
}

impl<E: std::error::Error> crate::ratelimit::MaybeRateLimited for EmailLinkInitError<E> {
    fn rate_limited(&self) -> Option<&crate::ratelimit::RateLimited> {
        match self {
            Self::SendingEmail(inner) => inner.rate_limited(),
            Self::NotAllowed(_) => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum EmailSignCallbackError<StoreError: std::error::Error> {
    #[error("{0} not allowed")]
    NotAllowed(crate::models::Intent),
    #[error("Challenge expired")]
    ChallengeExpired { address: String },
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    Resolve(crate::code_flow::ResolveUserError<StoreError>),
    #[error(transparent)]
    Store(StoreError),
}

impl<E: std::error::Error> From<EmailChallengeError<E>> for EmailSignCallbackError<E> {
    fn from(err: EmailChallengeError<E>) -> Self {
        match err {
            EmailChallengeError::Expired { address } => Self::ChallengeExpired { address },
            EmailChallengeError::NotFound => Self::ChallengeNotFound,
            EmailChallengeError::Store(inner) => Self::Store(inner),
        }
    }
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    /// Consume an emailed challenge and check its expiry.
    pub(crate) async fn consume_email_challenge(
        &self,
        code: String,
    ) -> Result<S::EmailChallenge, EmailChallengeError<S::Error>> {
        let Some(challenge) = self.store.consume_challenge(code).await? else {
            return Err(EmailChallengeError::NotFound);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(EmailChallengeError::Expired {
                address: challenge.get_address().to_owned(),
            });
        }

        Ok(challenge)
    }

    /// Whether emailed links serve this intent under the current policies.
    fn email_link_allowed(&self, intent: crate::models::Intent) -> bool {
        use crate::models::{Allow, Intent};

        self.email.offer_links
            && match intent {
                Intent::LogIn => self.login_allow(self.email.allow_login.as_ref()) != &Allow::Never,
                Intent::SignUp => {
                    self.signup_allow(self.email.allow_signup.as_ref()) != &Allow::Never
                }
            }
    }

    /// Send a login or signup link to the address.
    pub(crate) async fn email_sign_init(
        &self,
        intent: crate::models::Intent,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLinkInitError<S::Error>> {
        use crate::models::Intent;

        if !self.email_link_allowed(intent) {
            return Err(EmailLinkInitError::NotAllowed(intent));
        }

        let (route, kind) = match intent {
            Intent::LogIn => (self.routes.email.login_email.clone(), EmailLinkKind::LogIn),
            Intent::SignUp => (
                self.routes.email.signup_email.clone(),
                EmailLinkKind::SignUp,
            ),
        };

        self.send_email_challenge(route, email, kind, next).await?;

        Ok(())
    }

    /// Verify a link challenge and log the user in - creating the user or
    /// crossing over to login when the intent and policy allow it.
    pub(crate) async fn email_sign_callback(
        self,
        intent: crate::models::Intent,
        code: String,
    ) -> Result<(Self, Option<String>), EmailSignCallbackError<S::Error>> {
        use crate::models::User;

        if !self.email_link_allowed(intent) {
            return Err(EmailSignCallbackError::NotAllowed(intent));
        }

        let challenge = self.consume_email_challenge(code).await?;

        // Links resolve users exactly like the email code channel does.
        let user = self
            .resolve_user::<otp::EmailOtpFlow>(challenge.get_address(), intent)
            .await
            .map_err(EmailSignCallbackError::Resolve)?;

        Ok((
            self.log_in(
                crate::models::LoginMethod::Email {
                    address: challenge.get_address().to_owned(),
                },
                &user.get_id(),
            )
            .await
            .map_err(EmailSignCallbackError::Store)?,
            challenge.get_next().clone(),
        ))
    }
}
