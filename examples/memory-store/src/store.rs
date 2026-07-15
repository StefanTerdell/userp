use crate::models::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use authery::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        thiserror,
        uuid::Uuid,
    },
};

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, MyEmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
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
    type UserEmail = MyUserEmail;
    type LoginSession = MyLoginSession;
    type EmailChallenge = MyEmailChallenge;
    type OAuthToken = MyOAuthToken;
    type Error = MemoryStoreError;
    type UserId = Uuid;
    type SessionId = Uuid;
    type OAuthTokenId = Uuid;

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
    ) -> Result<Self::LoginSession, Self::Error> {
        let session = MyLoginSession {
            id: Uuid::new_v4(),
            user_id: *user_id,
            method,
        };

        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session.clone());

        Ok(session)
    }

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<MyUser>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.get(user_id).cloned())
    }

    async fn email_set_verified(&self, address: &str) -> Result<(), Self::Error> {
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

    async fn email_create_challenge(
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

    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error> {
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&code)
        };

        Ok(challenge)
    }

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

    async fn get_user_oauth_tokens(&self, user_id: &Uuid) -> Result<Vec<MyOAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect())
    }

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

    async fn delete_user(&self, id: &Uuid) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(id);
        sessions.retain(|_, session| session.user_id != *id);
        Ok(())
    }

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

    async fn delete_user_email(&self, user_id: &Uuid, address: String) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users
            .get_mut(user_id)
            .expect("User not found")
            .emails
            .retain(|e| e.email != address);
        Ok(())
    }

    async fn password_get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<Self::User>, Self::Error> {
        let users = self.users.read().await;

        Ok(users
            .values()
            .find(|u| u.emails.iter().any(|e| e.get_address() == password_id))
            .cloned())
    }

    async fn password_create_user(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<Self::User, Self::Error> {
        let mut users = self.users.write().await;

        if users
            .values()
            .any(|u| u.emails.iter().any(|e| e.get_address() == password_id))
        {
            return Err(MemoryStoreError::AddressInUse(password_id.to_string()));
        }

        let user_id = Uuid::new_v4();

        let user = Self::User {
            id: user_id,
            password_hash: Some(password_hash.into()),
            emails: vec![Self::UserEmail {
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
    async fn email_get_user_by_email_address(
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

    async fn email_create_user_by_email_address(
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

    async fn oauth_get_token_by_id(
        &self,
        token_id: &Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens.get(token_id).cloned())
    }

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

    async fn create_user_token_from_unmatched_token(
        &self,
        user_id: &Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;

        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            let mut users = self.users.write().await;

            if let Some(u) = users.get_mut(user_id) {
                u.emails.push(Self::UserEmail {
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

            user.emails.push(Self::UserEmail {
                user_id: user.id,
                email: address.to_string(),
                verified: false,
                allow_link_login: false,
            });
        };

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

    async fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<(Self::User, Self::OAuthToken)>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;
        let users = self.users.read().await;

        Ok(tokens
            .values()
            .find(|t| {
                t.provider_name == unmatched_token.provider_name
                    && t.provider_user_id == unmatched_token.provider_user_id
            })
            .and_then(|t| users.get(&t.user_id).map(|u| (u.clone(), t.clone()))))
    }
}
