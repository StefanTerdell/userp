//! Shared in-memory test store + harness for the integration tests. Built for
//! the recommended test feature set:
//!
//!   cargo test -p authery --no-default-features --features password,email,otp,mfa,user
#![allow(dead_code)]

use authery::core::CoreAuthery;
use authery::models::email::{EmailChallenge, UserEmail};
use authery::models::{AutheryCookies, LoginMethod, LoginSession, User};
use authery::prelude::{EmailConfig, PasswordConfig, SmtpSettings};
use authery::ratelimit::{NoRateLimit, RateLimiter};
use authery::reexports::chrono::{DateTime, Duration, Utc};
use authery::reexports::url::Url;
use authery::reexports::uuid::Uuid;
use authery::routes::Routes;
use authery::store::AutheryStore;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub emails: Vec<TestEmail>,
}

impl User for TestUser {
    type Id = Uuid;
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }
}

#[derive(Debug, Clone)]
pub struct TestEmail {
    pub user_id: Uuid,
    pub address: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

impl UserEmail for TestEmail {
    type UserId = Uuid;
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }
    fn get_address(&self) -> &str {
        &self.address
    }
    fn get_verified(&self) -> bool {
        self.verified
    }
    fn get_allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

#[cfg(feature = "sms")]
#[derive(Debug, Clone)]
pub struct TestPhone {
    pub user_id: Uuid,
    pub number: String,
    pub verified: bool,
    pub allow_login: bool,
}

#[cfg(feature = "sms")]
impl authery::models::sms::UserPhone for TestPhone {
    type UserId = Uuid;
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }
    fn get_number(&self) -> &str {
        &self.number
    }
    fn get_verified(&self) -> bool {
        self.verified
    }
    fn get_allow_login(&self) -> bool {
        self.allow_login
    }
}

#[derive(Debug, Clone)]
pub struct TestChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

impl EmailChallenge for TestChallenge {
    fn get_address(&self) -> &str {
        &self.address
    }
    fn get_code(&self) -> &str {
        &self.code
    }
    fn get_next(&self) -> &Option<String> {
        &self.next
    }
    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Debug, Clone)]
pub struct TestSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
    pub expires: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl LoginSession for TestSession {
    type Id = Uuid;
    type UserId = Uuid;
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }
    fn get_method(&self) -> LoginMethod {
        self.method.clone()
    }
    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
    fn get_last_seen(&self) -> Option<DateTime<Utc>> {
        self.last_seen
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestStore {
    pub users: Arc<Mutex<HashMap<Uuid, TestUser>>>,
    pub sessions: Arc<Mutex<HashMap<Uuid, TestSession>>>,
    pub challenges: Arc<Mutex<HashMap<String, TestChallenge>>>,
    #[cfg(feature = "totp")]
    pub totp: Arc<Mutex<HashMap<Uuid, authery::models::TotpCredential>>>,
    #[cfg(feature = "sms")]
    pub phones: Arc<Mutex<Vec<TestPhone>>>,
    #[cfg(feature = "mfa")]
    pub recovery: Arc<Mutex<HashMap<Uuid, Vec<String>>>>,
}

impl TestStore {
    /// Insert a user directly; `email` becomes a verified, link-login-enabled
    /// address (and doubles as the password id).
    pub fn seed_user(&self, email: &str, password_hash: Option<&str>) -> Uuid {
        let id = Uuid::new_v4();
        self.users.lock().unwrap().insert(
            id,
            TestUser {
                id,
                password_hash: password_hash.map(str::to_string),
                emails: vec![TestEmail {
                    user_id: id,
                    address: email.to_string(),
                    verified: true,
                    allow_link_login: true,
                }],
            },
        );
        id
    }

    /// Insert an email challenge directly, standing in for the SMTP send.
    pub fn seed_challenge(&self, code: &str, address: &str, expires_in: Duration) {
        self.challenges.lock().unwrap().insert(
            code.to_string(),
            TestChallenge {
                address: address.to_string(),
                code: code.to_string(),
                next: None,
                expires: Utc::now() + expires_in,
            },
        );
    }

    /// Attach a verified, login-enabled phone number to an existing user.
    #[cfg(feature = "sms")]
    pub fn seed_phone(&self, user_id: Uuid, number: &str) {
        self.phones.lock().unwrap().push(TestPhone {
            user_id,
            number: number.to_string(),
            verified: true,
            allow_login: true,
        });
    }

    pub fn session_count(&self, user_id: Uuid) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.user_id == user_id)
            .count()
    }
}

impl AutheryStore for TestStore {
    type Error = Infallible;
    type UserId = Uuid;
    type SessionId = Uuid;
    type User = TestUser;
    type LoginSession = TestSession;
    type UserEmail = TestEmail;
    type EmailChallenge = TestChallenge;
    #[cfg(feature = "sms")]
    type UserPhone = TestPhone;

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<TestUser>, Infallible> {
        Ok(self.users.lock().unwrap().get(user_id).cloned())
    }

    async fn create_session(
        &self,
        user_id: &Uuid,
        method: LoginMethod,
        expires: DateTime<Utc>,
    ) -> Result<TestSession, Infallible> {
        let session = TestSession {
            id: Uuid::new_v4(),
            user_id: *user_id,
            method,
            expires,
            last_seen: Some(Utc::now()),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id, session.clone());
        Ok(session)
    }

    async fn touch_session(
        &self,
        _user_id: &Uuid,
        session_id: &Uuid,
        seen_at: DateTime<Utc>,
    ) -> Result<(), Infallible> {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(session_id) {
            session.last_seen = Some(seen_at);
        }
        Ok(())
    }

    async fn get_session(&self, session_id: &Uuid) -> Result<Option<TestSession>, Infallible> {
        Ok(self.sessions.lock().unwrap().get(session_id).cloned())
    }

    async fn delete_session(&self, _user_id: &Uuid, session_id: &Uuid) -> Result<(), Infallible> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &Uuid) -> Result<Vec<TestSession>, Infallible> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect())
    }

    async fn delete_user(&self, id: &Uuid) -> Result<(), Infallible> {
        self.users.lock().unwrap().remove(id);
        Ok(())
    }

    #[cfg(feature = "totp")]
    async fn get_totp(
        &self,
        user_id: &Uuid,
    ) -> Result<Option<authery::models::TotpCredential>, Infallible> {
        Ok(self.totp.lock().unwrap().get(user_id).cloned())
    }

    #[cfg(feature = "totp")]
    async fn upsert_totp(
        &self,
        user_id: &Uuid,
        credential: authery::models::TotpCredential,
    ) -> Result<(), Infallible> {
        self.totp.lock().unwrap().insert(*user_id, credential);
        Ok(())
    }

    #[cfg(feature = "totp")]
    async fn delete_totp(&self, user_id: &Uuid) -> Result<(), Infallible> {
        self.totp.lock().unwrap().remove(user_id);
        Ok(())
    }

    #[cfg(feature = "sms")]
    async fn get_user_by_phone(
        &self,
        number: &str,
    ) -> Result<Option<(TestUser, TestPhone)>, Infallible> {
        let phone = self
            .phones
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.number == number)
            .cloned();
        Ok(phone.and_then(|p| {
            self.users
                .lock()
                .unwrap()
                .get(&p.user_id)
                .cloned()
                .map(|u| (u, p))
        }))
    }

    #[cfg(feature = "sms")]
    async fn create_user_by_phone(
        &self,
        number: &str,
    ) -> Result<(TestUser, TestPhone), Infallible> {
        let id = Uuid::new_v4();
        let user = TestUser {
            id,
            password_hash: None,
            emails: vec![],
        };
        let phone = TestPhone {
            user_id: id,
            number: number.to_string(),
            verified: true,
            allow_login: true,
        };
        self.users.lock().unwrap().insert(id, user.clone());
        self.phones.lock().unwrap().push(phone.clone());
        Ok((user, phone))
    }

    #[cfg(feature = "sms")]
    async fn get_user_phones(&self, user_id: &Uuid) -> Result<Vec<TestPhone>, Infallible> {
        Ok(self
            .phones
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.user_id == *user_id)
            .cloned()
            .collect())
    }

    #[cfg(feature = "mfa")]
    async fn set_recovery_code_hashes(
        &self,
        user_id: &Uuid,
        hashes: Vec<String>,
    ) -> Result<(), Infallible> {
        self.recovery.lock().unwrap().insert(*user_id, hashes);
        Ok(())
    }

    #[cfg(feature = "mfa")]
    async fn consume_recovery_code_hash(
        &self,
        user_id: &Uuid,
        hash: &str,
    ) -> Result<bool, Infallible> {
        let mut recovery = self.recovery.lock().unwrap();
        let Some(hashes) = recovery.get_mut(user_id) else {
            return Ok(false);
        };
        let before = hashes.len();
        hashes.retain(|h| h != hash);
        Ok(hashes.len() < before)
    }

    #[cfg(feature = "mfa")]
    async fn count_recovery_codes(&self, user_id: &Uuid) -> Result<usize, Infallible> {
        Ok(self
            .recovery
            .lock()
            .unwrap()
            .get(user_id)
            .map(Vec::len)
            .unwrap_or(0))
    }

    async fn get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<TestUser>, Infallible> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.emails.iter().any(|e| e.address == password_id))
            .cloned())
    }

    async fn create_user_by_password_id(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<TestUser, Infallible> {
        let id = Uuid::new_v4();
        let user = TestUser {
            id,
            password_hash: Some(password_hash.to_string()),
            emails: vec![TestEmail {
                user_id: id,
                address: password_id.to_string(),
                verified: false,
                allow_link_login: false,
            }],
        };
        self.users.lock().unwrap().insert(id, user.clone());
        Ok(user)
    }

    async fn clear_user_password_hash(
        &self,
        user_id: &Uuid,
        _session_id: &Uuid,
    ) -> Result<(), Infallible> {
        if let Some(user) = self.users.lock().unwrap().get_mut(user_id) {
            user.password_hash = None;
        }
        Ok(())
    }

    async fn set_user_password_hash(
        &self,
        user_id: &Uuid,
        password_hash: String,
        _session_id: &Uuid,
    ) -> Result<(), Infallible> {
        if let Some(user) = self.users.lock().unwrap().get_mut(user_id) {
            user.password_hash = Some(password_hash);
        }
        Ok(())
    }

    async fn get_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<Option<(TestUser, TestEmail)>, Infallible> {
        Ok(self.users.lock().unwrap().values().find_map(|u| {
            u.emails
                .iter()
                .find(|e| e.address == address)
                .map(|e| (u.clone(), e.clone()))
        }))
    }

    async fn create_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<(TestUser, TestEmail), Infallible> {
        let id = Uuid::new_v4();
        let email = TestEmail {
            user_id: id,
            address: address.to_string(),
            verified: true,
            allow_link_login: true,
        };
        let user = TestUser {
            id,
            password_hash: None,
            emails: vec![email.clone()],
        };
        self.users.lock().unwrap().insert(id, user.clone());
        Ok((user, email))
    }

    async fn set_email_verified(&self, address: &str) -> Result<(), Infallible> {
        for user in self.users.lock().unwrap().values_mut() {
            for email in &mut user.emails {
                if email.address == address {
                    email.verified = true;
                }
            }
        }
        Ok(())
    }

    async fn create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<TestChallenge, Infallible> {
        let challenge = TestChallenge {
            address,
            code: code.clone(),
            next,
            expires,
        };
        self.challenges
            .lock()
            .unwrap()
            .insert(code, challenge.clone());
        Ok(challenge)
    }

    async fn consume_challenge(&self, code: String) -> Result<Option<TestChallenge>, Infallible> {
        Ok(self.challenges.lock().unwrap().remove(&code))
    }

    async fn get_user_emails(&self, user_id: &Uuid) -> Result<Vec<TestEmail>, Infallible> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .get(user_id)
            .map(|u| u.emails.clone())
            .unwrap_or_default())
    }

    async fn set_user_email_allow_link_login(
        &self,
        user_id: &Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Infallible> {
        if let Some(user) = self.users.lock().unwrap().get_mut(user_id) {
            for email in &mut user.emails {
                if email.address == address {
                    email.allow_link_login = allow_login;
                }
            }
        }
        Ok(())
    }

    async fn add_user_email(&self, user_id: &Uuid, address: String) -> Result<(), Infallible> {
        if let Some(user) = self.users.lock().unwrap().get_mut(user_id) {
            user.emails.push(TestEmail {
                user_id: *user_id,
                address,
                verified: false,
                allow_link_login: false,
            });
        }
        Ok(())
    }

    async fn delete_user_email(&self, user_id: &Uuid, address: String) -> Result<(), Infallible> {
        if let Some(user) = self.users.lock().unwrap().get_mut(user_id) {
            user.emails.retain(|e| e.address != address);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestCookies(pub HashMap<String, String>);

impl AutheryCookies for TestCookies {
    fn add(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_string(), value.to_string());
    }
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn remove(&mut self, key: &str) {
        self.0.remove(key);
    }
    fn list_encoded(&self) -> Vec<String> {
        self.0.iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

/// A hasher that skips argon2 so flow tests run in microseconds. The hash IS
/// the password - never do this outside tests.
#[derive(Debug, Clone)]
pub struct PlaintextHasher;

impl authery::prelude::PasswordHasher for PlaintextHasher {
    fn generate_hash(&self, password: String) -> Pin<Box<dyn Future<Output = String> + Send>> {
        Box::pin(async move { password })
    }
    fn verify_password(
        &self,
        password: String,
        hash: String,
    ) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async move { password == hash })
    }
}

/// Collects sent texts instead of hitting a gateway - unlike SMTP this makes
/// the init step fully testable.
#[cfg(feature = "sms")]
#[derive(Debug, Clone, Default)]
pub struct TestSmsSender {
    pub sent: Arc<Mutex<Vec<(String, String)>>>,
}

#[cfg(feature = "sms")]
impl TestSmsSender {
    /// The code in the last text sent (codes lead the message body).
    pub fn last_code(&self) -> String {
        self.sent
            .lock()
            .unwrap()
            .last()
            .and_then(|(_, message)| message.split_whitespace().next())
            .expect("no sms sent")
            .to_string()
    }
}

#[cfg(feature = "sms")]
impl authery::sms::SmsSender for TestSmsSender {
    fn send<'a>(&'a self, to: &'a str, message: &'a str) -> authery::sms::SmsSendFuture<'a> {
        self.sent
            .lock()
            .unwrap()
            .push((to.to_string(), message.to_string()));
        Box::pin(async { Ok(()) })
    }
}

pub struct AuthBuilder {
    pub store: TestStore,
    pub session_lifetime: Duration,
    pub max_concurrent_sessions: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub mfa_policy: authery::mfa::MfaPolicy,
    #[cfg(feature = "sms")]
    pub sms_sender: TestSmsSender,
}

impl AuthBuilder {
    pub fn new(store: TestStore) -> Self {
        Self {
            store,
            session_lifetime: Duration::days(1),
            max_concurrent_sessions: None,
            idle_timeout: None,
            rate_limiter: Arc::new(NoRateLimit),
            #[cfg(feature = "sms")]
            sms_sender: TestSmsSender::default(),
            mfa_policy: authery::mfa::MfaPolicy {
                require_for_password: false,
                ..Default::default()
            },
        }
    }

    pub fn build(self) -> CoreAuthery<TestStore, TestCookies> {
        CoreAuthery {
            routes: Routes::default().with_prefix(""),
            allow_signup: authery::models::Allow::OnSelf,
            allow_login: authery::models::Allow::OnSelf,
            session_lifetime: self.session_lifetime,
            max_concurrent_sessions: self.max_concurrent_sessions,
            idle_timeout: self.idle_timeout,
            rate_limiter: self.rate_limiter,
            events: Arc::new(authery::events::TracingEvents),
            bearer_token: None,
            cookies: TestCookies::default(),
            store: self.store,
            pass: PasswordConfig::new().with_hasher(PlaintextHasher),
            #[cfg(feature = "totp")]
            totp: authery::totp::TotpConfig::new("authery-tests"),
            #[cfg(feature = "sms")]
            sms: authery::sms::SmsConfig::new(self.sms_sender.clone()),
            email: EmailConfig::new(
                Url::parse("http://localhost:3000").unwrap(),
                SmtpSettings::new("smtp://localhost:1", "test@example.com"),
            ),
            mfa_policy: self.mfa_policy,
        }
    }
}

pub fn auth(store: &TestStore) -> CoreAuthery<TestStore, TestCookies> {
    AuthBuilder::new(store.clone()).build()
}
