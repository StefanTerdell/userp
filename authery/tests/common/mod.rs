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
}

#[derive(Debug, Clone, Default)]
pub struct TestStore {
    pub users: Arc<Mutex<HashMap<Uuid, TestUser>>>,
    pub sessions: Arc<Mutex<HashMap<Uuid, TestSession>>>,
    pub challenges: Arc<Mutex<HashMap<String, TestChallenge>>>,
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
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id, session.clone());
        Ok(session)
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

    async fn password_get_user_by_password_id(
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

    async fn password_create_user(
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

    async fn email_get_user_by_email_address(
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

    async fn email_create_user_by_email_address(
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

    async fn email_set_verified(&self, address: &str) -> Result<(), Infallible> {
        for user in self.users.lock().unwrap().values_mut() {
            for email in &mut user.emails {
                if email.address == address {
                    email.verified = true;
                }
            }
        }
        Ok(())
    }

    async fn email_create_challenge(
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

    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<TestChallenge>, Infallible> {
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

pub struct AuthBuilder {
    pub store: TestStore,
    pub session_lifetime: Duration,
    pub max_concurrent_sessions: Option<usize>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub mfa_policy: authery::mfa::MfaPolicy,
}

impl AuthBuilder {
    pub fn new(store: TestStore) -> Self {
        Self {
            store,
            session_lifetime: Duration::days(1),
            max_concurrent_sessions: None,
            rate_limiter: Arc::new(NoRateLimit),
            mfa_policy: authery::mfa::MfaPolicy {
                require_for_password: false,
                require_for_email: false,
                require_for_otp: false,
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
            rate_limiter: self.rate_limiter,
            cookies: TestCookies::default(),
            store: self.store,
            pass: PasswordConfig::new().with_hasher(PlaintextHasher),
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
