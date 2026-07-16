pub mod login;
#[cfg(feature = "otp")]
pub mod otp;
#[cfg(feature = "password")]
pub mod reset;
pub mod signup;
pub mod verify;

use chrono::{Duration, Utc};
use lettre::{
    message::header::ContentType, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    core::CoreAuthery,
    models::{email::EmailChallenge, AutheryCookies},
    store::AutheryStore,
};
use crate::models::Allow;

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub challenge_lifetime: Duration,
    pub base_url: Url,
    pub smtp: SmtpSettings,
}

impl EmailConfig {
    pub fn new(base_url: Url, smtp: SmtpSettings) -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            challenge_lifetime: Duration::minutes(5),
            base_url,
            smtp,
        }
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

#[derive(Debug, Error)]
pub enum SendEmailChallengeError<StoreError: std::error::Error> {
    #[error(transparent)]
    RateLimited(crate::ratelimit::RateLimited),
    #[error(transparent)]
    Url(url::ParseError),
    #[error(transparent)]
    Address(lettre::address::AddressError),
    #[error(transparent)]
    MessageBuilding(lettre::error::Error),
    #[error(transparent)]
    Transport(lettre::transport::smtp::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    async fn send_email_challenge(
        &self,
        path: String,
        address: String,
        message: String,
        next: Option<String>,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        self.rate_limiter
            .check(crate::ratelimit::RateLimitOp::EmailSend { address: &address })
            .await
            .map_err(SendEmailChallengeError::RateLimited)?;

        let code = Uuid::new_v4().to_string().replace('-', "");

        let challenge = self
            .store
            .email_create_challenge(
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

        self.send_email(
            challenge.get_address(),
            "Login link",
            format!("<a href=\"{url}\">{message}</a>"),
        )
        .await
    }

    async fn send_email(
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
