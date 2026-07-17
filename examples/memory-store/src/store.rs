#[cfg(any(feature = "email", feature = "sms"))]
use crate::models::MyEmailChallenge;
#[cfg(any(feature = "email", feature = "password", feature = "oauth"))]
use crate::models::MyUserEmail;
#[cfg(feature = "sms")]
use crate::models::MyUserPhone;
#[cfg(feature = "oauth")]
use crate::models::{AppOrg, AppOrgMember, AppOrgProvider, MyOAuthToken};
use crate::models::{MyLoginSession, MyUser};
#[cfg(feature = "webauthn")]
use authery::reexports::webauthn_rs::prelude::Passkey;
use authery::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        thiserror,
        uuid::Uuid,
    },
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    #[cfg(any(feature = "email", feature = "sms"))]
    challenges: Arc<RwLock<HashMap<String, MyEmailChallenge>>>,
    #[cfg(feature = "oauth")]
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
    /// Passkeys keyed by raw credential id, with their owning user.
    #[cfg(feature = "webauthn")]
    #[allow(clippy::type_complexity)]
    passkeys: Arc<RwLock<HashMap<Vec<u8>, (Uuid, Passkey)>>>,
    #[cfg(feature = "totp")]
    totp: Arc<RwLock<HashMap<Uuid, TotpCredential>>>,
    #[cfg(feature = "sms")]
    phones: Arc<RwLock<Vec<MyUserPhone>>>,
    #[cfg(feature = "mfa")]
    recovery: Arc<RwLock<HashMap<Uuid, Vec<String>>>>,
    /// App-level org tables - authery knows nothing about these; see the
    /// multi-tenant example.
    #[cfg(feature = "oauth")]
    pub orgs: Arc<RwLock<HashMap<Uuid, AppOrg>>>,
    #[cfg(feature = "oauth")]
    pub org_members: Arc<RwLock<Vec<AppOrgMember>>>,
    #[cfg(feature = "oauth")]
    pub org_providers: Arc<RwLock<Vec<AppOrgProvider>>>,
}

#[derive(thiserror::Error, Debug)]
pub enum MemoryStoreError {
    #[error("The email address is already in use: {0}")]
    AddressInUse(String),
    #[error("The token was not found: {0}")]
    TokenNotFound(String),
    #[error("User mismatch")]
    WrongUserId,
}

impl IntoResponse for MemoryStoreError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

impl AutheryStore for MemoryStore {
    type User = MyUser;
    #[cfg(feature = "email")]
    type UserEmail = MyUserEmail;
    #[cfg(feature = "sms")]
    type UserPhone = MyUserPhone;
    type LoginSession = MyLoginSession;
    #[cfg(any(feature = "email", feature = "sms"))]
    type EmailChallenge = MyEmailChallenge;
    #[cfg(feature = "oauth")]
    type OAuthToken = MyOAuthToken;
    type Error = MemoryStoreError;
    type UserId = Uuid;
    type SessionId = Uuid;
    #[cfg(feature = "oauth")]
    type OAuthTokenId = Uuid;

    #[cfg(feature = "webauthn")]
    async fn create_passkey(&self, user_id: &Uuid, passkey: Passkey) -> Result<(), Self::Error> {
        let mut passkeys = self.passkeys.write().await;

        passkeys.insert(passkey.cred_id().to_vec(), (*user_id, passkey));

        Ok(())
    }

    #[cfg(feature = "webauthn")]
    async fn get_passkeys(&self, user_id: &Uuid) -> Result<Vec<Passkey>, Self::Error> {
        let passkeys = self.passkeys.read().await;

        Ok(passkeys
            .values()
            .filter(|(id, _)| id == user_id)
            .map(|(_, p)| p.clone())
            .collect())
    }

    #[cfg(feature = "webauthn")]
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<(Uuid, Passkey)>, Self::Error> {
        let passkeys = self.passkeys.read().await;

        Ok(passkeys.get(credential_id).cloned())
    }

    #[cfg(feature = "webauthn")]
    async fn update_passkey(&self, user_id: &Uuid, passkey: Passkey) -> Result<(), Self::Error> {
        let mut passkeys = self.passkeys.write().await;

        match passkeys.get(passkey.cred_id().as_slice()) {
            Some((owner, _)) if owner == user_id => {
                passkeys.insert(passkey.cred_id().to_vec(), (*user_id, passkey));
                Ok(())
            }
            Some(_) => Err(MemoryStoreError::WrongUserId),
            None => Err(MemoryStoreError::TokenNotFound(format!(
                "{:x?}",
                passkey.cred_id()
            ))),
        }
    }

    #[cfg(all(feature = "webauthn", feature = "user"))]
    async fn delete_passkey(
        &self,
        user_id: &Uuid,
        credential_id: &[u8],
    ) -> Result<(), Self::Error> {
        let mut passkeys = self.passkeys.write().await;

        match passkeys.get(credential_id) {
            Some((owner, _)) if owner == user_id => {
                passkeys.remove(credential_id);
                Ok(())
            }
            Some(_) => Err(MemoryStoreError::WrongUserId),
            None => Ok(()),
        }
    }

    #[cfg(feature = "totp")]
    async fn get_totp(&self, user_id: &Uuid) -> Result<Option<TotpCredential>, Self::Error> {
        Ok(self.totp.read().await.get(user_id).cloned())
    }

    #[cfg(feature = "totp")]
    async fn upsert_totp(
        &self,
        user_id: &Uuid,
        credential: TotpCredential,
    ) -> Result<(), Self::Error> {
        self.totp.write().await.insert(*user_id, credential);

        Ok(())
    }

    #[cfg(feature = "totp")]
    async fn delete_totp(&self, user_id: &Uuid) -> Result<(), Self::Error> {
        self.totp.write().await.remove(user_id);

        Ok(())
    }

    async fn touch_session(
        &self,
        _user_id: &Uuid,
        session_id: &Uuid,
        seen_at: DateTime<Utc>,
    ) -> Result<(), MemoryStoreError> {
        if let Some(session) = self.sessions.write().await.get_mut(session_id) {
            session.last_seen = Some(seen_at);
        }
        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error> {
        let sessions = self.sessions.read().await;

        Ok(sessions.get(session_id).cloned())
    }

    async fn delete_session(&self, user_id: &Uuid, session_id: &Uuid) -> Result<(), Self::Error> {
        let mut sessions = self.sessions.write().await;

        match sessions.remove(session_id) {
            Some(s) if s.user_id != *user_id => {
                sessions.insert(s.id, s);
                Err(MemoryStoreError::WrongUserId)
            }
            _ => Ok(()),
        }
    }

    async fn create_session(
        &self,
        user_id: &Uuid,
        method: LoginMethod,
        expires: DateTime<Utc>,
    ) -> Result<Self::LoginSession, Self::Error> {
        let session = MyLoginSession {
            id: Uuid::new_v4(),
            user_id: *user_id,
            method,
            expires,
            last_seen: Some(Utc::now()),
        };

        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session.clone());

        Ok(session)
    }

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<MyUser>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.get(user_id).cloned())
    }

    #[cfg(feature = "email")]
    async fn set_email_verified(&self, address: &str) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users.values_mut().for_each(|u| {
            u.emails.iter_mut().for_each(|e| {
                if e.email == address {
                    e.verified = true
                }
            });
        });

        Ok(())
    }

    #[cfg(any(feature = "email", feature = "sms"))]
    async fn create_challenge(
        &self,

        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<Self::EmailChallenge, Self::Error> {
        let challenge = MyEmailChallenge {
            address,
            code,
            next,
            expires,
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.code.clone(), challenge.clone());

        Ok(challenge)
    }

    #[cfg(any(feature = "email", feature = "sms"))]
    async fn consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error> {
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&code)
        };

        Ok(challenge)
    }

    #[cfg(feature = "email")]
    async fn get_user_emails(&self, user_id: &Uuid) -> Result<Vec<MyUserEmail>, Self::Error> {
        let users = self.users.read().await;

        Ok(users
            .get(user_id)
            .map(|u| u.emails.clone())
            .unwrap_or_default())
    }

    async fn get_user_sessions(&self, user_id: &Uuid) -> Result<Vec<MyLoginSession>, Self::Error> {
        let sessions = self.sessions.read().await;

        Ok(sessions
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect())
    }

    #[cfg(all(feature = "user", feature = "oauth"))]
    async fn get_user_oauth_tokens(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<MyOAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect())
    }

    #[cfg(all(feature = "user", feature = "oauth"))]
    async fn delete_oauth_token(&self, user_id: &Uuid, token_id: &Uuid) -> Result<(), Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;

        match tokens.remove(token_id) {
            Some(t) if t.user_id != *user_id => {
                tokens.insert(t.id, t);
                Err(MemoryStoreError::WrongUserId)
            }
            _ => Ok(()),
        }
    }

    #[cfg(feature = "user")]
    async fn delete_user(&self, id: &Uuid) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(id);
        sessions.retain(|_, session| session.user_id != *id);
        Ok(())
    }

    #[cfg(all(feature = "user", feature = "password"))]
    async fn clear_user_password_hash(
        &self,
        user_id: &Uuid,
        session_id: &Uuid,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != *user_id
                    || session.method != LoginMethod::Password
                    || session.id == *session_id
            });

            user.password_hash = None
        }
        Ok(())
    }

    #[cfg(all(any(feature = "user", feature = "email"), feature = "password"))]
    async fn set_user_password_hash(
        &self,
        user_id: &Uuid,
        password_hash: String,
        session_id: &Uuid,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != *user_id
                    || session.method != LoginMethod::Password
                    || session.id == *session_id
            });

            user.password_hash = Some(password_hash)
        };
        Ok(())
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn set_user_email_allow_link_login(
        &self,
        user_id: &Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users.get_mut(user_id).map(|u| {
            u.emails
                .iter_mut()
                .find(|e| e.email == address)
                .map(|e| e.allow_link_login = allow_login)
        });
        Ok(())
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn add_user_email(&self, user_id: &Uuid, address: String) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        if users
            .values()
            .any(|u| u.id != *user_id && u.emails.iter().any(|e| e.email == address))
        {
            return Err(MemoryStoreError::AddressInUse(address));
        }

        let emails = &mut users.get_mut(user_id).expect("User not found").emails;

        if !emails.iter().any(|e| e.email == address) {
            emails.push(MyUserEmail {
                user_id: *user_id,
                email: address,
                verified: false,
                allow_link_login: false,
            });
        }

        Ok(())
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn delete_user_email(&self, user_id: &Uuid, address: String) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users
            .get_mut(user_id)
            .expect("User not found")
            .emails
            .retain(|e| e.email != address);
        Ok(())
    }

    #[cfg(feature = "sms")]
    async fn get_user_by_phone(
        &self,
        number: &str,
    ) -> Result<Option<(Self::User, Self::UserPhone)>, Self::Error> {
        let phones = self.phones.read().await;
        let users = self.users.read().await;

        Ok(phones
            .iter()
            .find(|p| p.number == number)
            .and_then(|p| users.get(&p.user_id).map(|u| (u.clone(), p.clone()))))
    }

    #[cfg(feature = "sms")]
    async fn create_user_by_phone(
        &self,
        number: &str,
    ) -> Result<(Self::User, Self::UserPhone), Self::Error> {
        let mut users = self.users.write().await;
        let mut phones = self.phones.write().await;

        let user = Self::User {
            id: Uuid::new_v4(),
            password_hash: None,
            emails: vec![],
        };

        // The user just proved control of the number, so it starts verified.
        let phone = MyUserPhone {
            user_id: user.id,
            number: number.to_string(),
            verified: true,
            allow_login: true,
        };

        users.insert(user.id, user.clone());
        phones.push(phone.clone());

        Ok((user, phone))
    }

    #[cfg(feature = "sms")]
    async fn get_user_phones(&self, user_id: &Uuid) -> Result<Vec<MyUserPhone>, Self::Error> {
        let phones = self.phones.read().await;

        Ok(phones
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
    ) -> Result<(), MemoryStoreError> {
        self.recovery.write().await.insert(*user_id, hashes);
        Ok(())
    }

    #[cfg(feature = "mfa")]
    async fn consume_recovery_code_hash(
        &self,
        user_id: &Uuid,
        hash: &str,
    ) -> Result<bool, MemoryStoreError> {
        let mut recovery = self.recovery.write().await;
        let Some(hashes) = recovery.get_mut(user_id) else {
            return Ok(false);
        };
        let before = hashes.len();
        hashes.retain(|h| h != hash);
        Ok(hashes.len() < before)
    }

    #[cfg(feature = "mfa")]
    async fn count_recovery_codes(&self, user_id: &Uuid) -> Result<usize, MemoryStoreError> {
        Ok(self
            .recovery
            .write()
            .await
            .get(user_id)
            .map(Vec::len)
            .unwrap_or(0))
    }

    #[cfg(feature = "password")]
    async fn get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<Self::User>, Self::Error> {
        let users = self.users.read().await;

        Ok(users
            .values()
            .find(|u| u.emails.iter().any(|e| e.email == password_id))
            .cloned())
    }

    #[cfg(feature = "password")]
    async fn create_user_by_password_id(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<Self::User, Self::Error> {
        let mut users = self.users.write().await;

        if users
            .values()
            .any(|u| u.emails.iter().any(|e| e.email == password_id))
        {
            return Err(MemoryStoreError::AddressInUse(password_id.to_string()));
        }

        let user_id = Uuid::new_v4();

        let user = Self::User {
            id: user_id,
            password_hash: Some(password_hash.into()),
            emails: vec![MyUserEmail {
                user_id,
                email: password_id.into(),
                verified: false,
                allow_link_login: false,
            }],
        };

        users.insert(user_id, user.clone());

        Ok(user)
    }

    // user store
    #[cfg(feature = "email")]
    async fn get_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<Option<(Self::User, Self::UserEmail)>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.values().find_map(|u| {
            u.emails
                .iter()
                .find(|e| e.get_address() == address)
                .map(|e| (u.clone(), e.clone()))
        }))
    }

    #[cfg(feature = "email")]
    async fn create_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<(Self::User, Self::UserEmail), Self::Error> {
        let mut users = self.users.write().await;

        if users
            .values()
            .any(|u| u.emails.iter().any(|e| e.get_address() == address))
        {
            return Err(MemoryStoreError::AddressInUse(address.into()));
        }

        let user_id = Uuid::new_v4();

        let email = Self::UserEmail {
            user_id,
            email: address.into(),
            verified: true,
            allow_link_login: true,
        };

        let user = Self::User {
            id: user_id,
            password_hash: None,
            emails: vec![email.clone()],
        };

        users.insert(user_id, user.clone());

        Ok((user, email))
    }

    #[cfg(feature = "oauth")]
    async fn update_token_by_unmatched_token(
        &self,
        token_id: &Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;

        let prev = tokens
            .get_mut(token_id)
            .ok_or(MemoryStoreError::TokenNotFound(token_id.to_string()))?;

        prev.provider_name = unmatched_token.provider_name;
        prev.provider_user_id = unmatched_token.provider_user_id;
        prev.access_token = unmatched_token.access_token;
        prev.refresh_token = unmatched_token.refresh_token;
        prev.expires = unmatched_token.expires;
        prev.scopes = unmatched_token.scopes;

        Ok(prev.clone())
    }

    #[cfg(feature = "oauth")]
    async fn get_oauth_token_by_id(
        &self,
        token_id: &Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens.get(token_id).cloned())
    }

    #[cfg(feature = "oauth")]
    async fn get_token_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens
            .values()
            .find(|t| {
                t.provider_name == unmatched_token.provider_name
                    && t.provider_user_id == unmatched_token.provider_user_id
            })
            .cloned())
    }

    #[cfg(feature = "oauth")]
    async fn create_user_token_from_unmatched_token(
        &self,
        user_id: &Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;

        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            let mut users = self.users.write().await;

            if let Some(u) = users.get_mut(user_id) {
                u.emails.push(MyUserEmail {
                    user_id: u.id,
                    email: address.to_string(),
                    verified: false,
                    allow_link_login: false,
                })
            }
        };

        let token = Self::OAuthToken {
            id: Uuid::new_v4(),
            user_id: *user_id,
            provider_name: unmatched_token.provider_name,
            provider_user_id: unmatched_token.provider_user_id,
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            scopes: unmatched_token.scopes,
        };

        tokens.insert(token.id, token.clone());

        Ok(token)
    }

    #[cfg(feature = "oauth")]
    async fn create_user_from_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<(Self::User, Self::OAuthToken), Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;
        let mut users = self.users.write().await;

        let mut user = Self::User {
            id: Uuid::new_v4(),
            password_hash: None,
            emails: vec![],
        };

        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            if users
                .values()
                .any(|u| u.emails.iter().any(|e| e.email == address))
            {
                return Err(MemoryStoreError::AddressInUse(address.to_string()));
            };

            user.emails.push(MyUserEmail {
                user_id: user.id,
                email: address.to_string(),
                verified: false,
                allow_link_login: false,
            });
        };

        self.apply_org_context(&unmatched_token, user.id).await;

        let token = Self::OAuthToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider_name: unmatched_token.provider_name,
            provider_user_id: unmatched_token.provider_user_id,
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            scopes: unmatched_token.scopes,
        };

        tokens.insert(token.id, token.clone());
        users.insert(user.id, user.clone());

        Ok((user, token))
    }

    #[cfg(feature = "oauth")]
    async fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<(Self::User, Self::OAuthToken)>, Self::Error> {
        let found = {
            let tokens = self.oauth_tokens.read().await;
            let users = self.users.read().await;

            tokens
                .values()
                .find(|t| {
                    t.provider_name == unmatched_token.provider_name
                        && t.provider_user_id == unmatched_token.provider_user_id
                })
                .and_then(|t| users.get(&t.user_id).map(|u| (u.clone(), t.clone())))
        };

        if let Some((user, _)) = &found {
            self.apply_org_context(&unmatched_token, user.id).await;
        }

        Ok(found)
    }
}

#[cfg(feature = "oauth")]
impl MemoryStore {
    /// App-level org logic, run wherever the store observes an oauth login
    /// carrying a provider-resolution context: upsert the user as a member of
    /// the org the context names. Claim mapping is plain app code - here, the
    /// admin flag comes from a Keycloak realm role in the validated id_token.
    async fn apply_org_context(&self, unmatched_token: &UnmatchedOAuthToken, user_id: Uuid) {
        let Some(slug) = unmatched_token.context.as_deref() else {
            return;
        };
        let Some(org_id) = self
            .orgs
            .read()
            .await
            .values()
            .find(|o| o.slug == slug)
            .map(|o| o.id)
        else {
            return;
        };

        let admin = unmatched_token.provider_user_raw["realm_access"]["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some("authery-admin")));

        let mut members = self.org_members.write().await;
        members.retain(|m| !(m.org_id == org_id && m.user_id == user_id));
        members.push(AppOrgMember {
            user_id,
            org_id,
            admin,
        });
    }
}
