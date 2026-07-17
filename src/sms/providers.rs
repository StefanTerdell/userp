//! Ready-made [`SmsSender`] implementations for popular SMS providers
//! (enabled by the `sms-providers` feature, which pulls in an HTTP client).
//! Each is a thin call to the provider's HTTP API - bring your own
//! implementation for anything not covered, or for provider SDKs.
//!
//! None of these are exercised by authery's test suite (they need live
//! accounts); they are kept deliberately simple enough to review at a glance.

use super::{SmsSendFuture, SmsSender};
use serde_json::json;

fn provider_error(provider: &str, detail: String) -> super::SmsSendError {
    format!("{provider}: {detail}").into()
}

/// [Twilio](https://www.twilio.com/docs/sms/api) - `Messages.json` with basic
/// auth.
#[derive(Debug, Clone)]
pub struct TwilioSmsSender {
    pub account_sid: String,
    pub auth_token: String,
    /// The sending number or alphanumeric sender id.
    pub from: String,
}

impl TwilioSmsSender {
    pub fn new(
        account_sid: impl Into<String>,
        auth_token: impl Into<String>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            account_sid: account_sid.into(),
            auth_token: auth_token.into(),
            from: from.into(),
        }
    }
}

impl SmsSender for TwilioSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move {
            reqwest::Client::new()
                .post(format!(
                    "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
                    self.account_sid
                ))
                .basic_auth(&self.account_sid, Some(&self.auth_token))
                .form(&[("To", to), ("From", &self.from), ("Body", message)])
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }
}

/// [Vonage (Nexmo)](https://developer.vonage.com/en/messaging/sms/overview) -
/// `sms/json`. Vonage reports per-message errors in a 200 body, so the status
/// field is checked explicitly.
#[derive(Debug, Clone)]
pub struct VonageSmsSender {
    pub api_key: String,
    pub api_secret: String,
    pub from: String,
}

impl VonageSmsSender {
    pub fn new(
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            api_secret: api_secret.into(),
            from: from.into(),
        }
    }
}

impl SmsSender for VonageSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move {
            let body = reqwest::Client::new()
                .post("https://rest.nexmo.com/sms/json")
                .form(&[
                    ("api_key", self.api_key.as_str()),
                    ("api_secret", self.api_secret.as_str()),
                    ("from", self.from.as_str()),
                    ("to", to),
                    ("text", message),
                ])
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?;

            let status = body["messages"][0]["status"].as_str().unwrap_or("unknown");
            if status != "0" {
                let text = body["messages"][0]["error-text"]
                    .as_str()
                    .unwrap_or("unknown error");
                return Err(provider_error("vonage", format!("status {status}: {text}")));
            }

            Ok(())
        })
    }
}

/// [MessageBird](https://developers.messagebird.com/api/sms-messaging/) -
/// `messages` with an AccessKey header.
#[derive(Debug, Clone)]
pub struct MessageBirdSmsSender {
    pub access_key: String,
    /// The originator: a number or alphanumeric sender id.
    pub originator: String,
}

impl MessageBirdSmsSender {
    pub fn new(access_key: impl Into<String>, originator: impl Into<String>) -> Self {
        Self {
            access_key: access_key.into(),
            originator: originator.into(),
        }
    }
}

impl SmsSender for MessageBirdSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move {
            reqwest::Client::new()
                .post("https://rest.messagebird.com/messages")
                .header("Authorization", format!("AccessKey {}", self.access_key))
                .json(&json!({
                    "originator": self.originator,
                    "recipients": [to],
                    "body": message,
                }))
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }
}

/// [Telnyx](https://developers.telnyx.com/docs/messaging) - `v2/messages`
/// with a bearer key.
#[derive(Debug, Clone)]
pub struct TelnyxSmsSender {
    pub api_key: String,
    pub from: String,
}

impl TelnyxSmsSender {
    pub fn new(api_key: impl Into<String>, from: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            from: from.into(),
        }
    }
}

impl SmsSender for TelnyxSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move {
            reqwest::Client::new()
                .post("https://api.telnyx.com/v2/messages")
                .bearer_auth(&self.api_key)
                .json(&json!({
                    "from": self.from,
                    "to": to,
                    "text": message,
                }))
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }
}

/// [46elks](https://46elks.com/docs/send-sms) - `a1/sms` with basic auth.
#[derive(Debug, Clone)]
pub struct FortySixElksSmsSender {
    pub username: String,
    pub password: String,
    /// The sender: a number or alphanumeric sender id.
    pub from: String,
}

impl FortySixElksSmsSender {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            from: from.into(),
        }
    }
}

impl SmsSender for FortySixElksSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> SmsSendFuture<'a> {
        Box::pin(async move {
            reqwest::Client::new()
                .post("https://api.46elks.com/a1/sms")
                .basic_auth(&self.username, Some(&self.password))
                .form(&[
                    ("from", self.from.as_str()),
                    ("to", to),
                    ("message", message),
                ])
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        })
    }
}
