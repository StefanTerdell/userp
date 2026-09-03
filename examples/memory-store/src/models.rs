use authery::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        uuid::Uuid,
    },
};

#[derive(Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    #[allow(dead_code)]
    pub password_hash: Option<String>,
    /// Doubles as the password-id lookup, so present for `password` too.
    #[allow(dead_code)]
    pub emails: Vec<MyUserEmail>,
}

impl User for MyUser {
    type Id = Uuid;

    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug, Clone)]
pub struct MyUserEmail {
    pub user_id: Uuid,
    pub email: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

#[cfg(feature = "email")]
impl UserEmail for MyUserEmail {
    type UserId = Uuid;

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_address(&self) -> &str {
        self.email.as_str()
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
pub struct MyUserPhone {
    pub user_id: Uuid,
    pub number: String,
    pub verified: bool,
    pub allow_login: bool,
}

#[cfg(feature = "sms")]
impl UserPhone for MyUserPhone {
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
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
    pub expires: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub meta: SessionMeta,
}

impl LoginSession for MyLoginSession {
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

    fn get_user_agent(&self) -> Option<&str> {
        self.meta.user_agent.as_deref()
    }

    fn get_ip_address(&self) -> Option<&str> {
        self.meta.ip_address.as_deref()
    }
}

#[cfg(any(feature = "email", feature = "sms"))]
#[derive(Clone, Debug)]
pub struct MyEmailChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

#[cfg(any(feature = "email", feature = "sms"))]
impl EmailChallenge for MyEmailChallenge {
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

#[cfg(feature = "oauth")]
#[derive(Clone, Debug)]
#[allow(unused)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

#[cfg(feature = "oauth")]
impl OAuthToken for MyOAuthToken {
    type Id = Uuid;
    type UserId = Uuid;

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_scopes(&self) -> Option<Vec<String>> {
        Some(self.scopes.clone())
    }

    fn get_provider_name(&self) -> &str {
        self.provider_name.as_str()
    }

    fn get_refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }
}

// --- App-level organizations ---
//
// Orgs are the app's domain, not authery's: plain structs in the app's own
// store, no authery traits involved. Authery's contribution is the dynamic
// provider resolver + the `context` string that rides the oauth flow and
// arrives on `UnmatchedOAuthToken` at user/token creation - which is where
// `MemoryStore` below upserts memberships.

#[cfg(feature = "oauth")]
#[derive(Debug, Clone)]
pub struct AppOrg {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    /// Enforced by the app's own routes via `LoginMethodRules`.
    pub login_rules: LoginMethodRules,
}

#[cfg(feature = "oauth")]
#[derive(Debug, Clone)]
pub struct AppOrgMember {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub admin: bool,
}

/// Per-org OIDC provider config; built into a live provider by the app's
/// `OAuthProviderResolver` impl.
#[cfg(feature = "oauth")]
#[derive(Debug, Clone)]
pub struct AppOrgProvider {
    pub org_id: Uuid,
    pub name: String,
    pub display_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub auth_url: String,
    pub token_url: String,
}
