use crate::models::{
    MyEmailChallenge, MyLoginSession, MyOAuthToken, MyOrgInvite, MyOrgMember, MyOrgOidcProvider,
    MyOrganization, MyUser, MyUserEmail,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use authery::{
    models::org::{NewOrgOidcProvider, OrgLoginRules, OrgPrivilege},
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        thiserror,
        uuid::Uuid,
        webauthn_rs::prelude::Passkey,
    },
};

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, MyEmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
    /// Passkeys keyed by raw credential id, with their owning user.
    #[allow(clippy::type_complexity)]
    passkeys: Arc<RwLock<HashMap<Vec<u8>, (Uuid, Passkey)>>>,
    orgs: Arc<RwLock<HashMap<Uuid, MyOrganization>>>,
    org_members: Arc<RwLock<Vec<MyOrgMember>>>,
    org_oidc_providers: Arc<RwLock<Vec<MyOrgOidcProvider>>>,
    org_invites: Arc<RwLock<HashMap<String, MyOrgInvite>>>,
}

#[derive(thiserror::Error, Debug)]
pub enum MemoryStoreError {
    #[error("The email address is already in use: {0}")]
    AddressInUse(String),
    #[error("The org slug is already in use: {0}")]
    SlugInUse(String),
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
    type OrgId = Uuid;
    type Organization = MyOrganization;
    type OrgMember = MyOrgMember;
    type OrgInvite = MyOrgInvite;
    type OrgOidcProvider = MyOrgOidcProvider;

    async fn webauthn_create_credential(
        &self,
        user_id: &Uuid,
        passkey: Passkey,
    ) -> Result<(), Self::Error> {
        let mut passkeys = self.passkeys.write().await;

        passkeys.insert(passkey.cred_id().to_vec(), (*user_id, passkey));

        Ok(())
    }

    async fn webauthn_get_credentials(&self, user_id: &Uuid) -> Result<Vec<Passkey>, Self::Error> {
        let passkeys = self.passkeys.read().await;

        Ok(passkeys
            .values()
            .filter(|(id, _)| id == user_id)
            .map(|(_, p)| p.clone())
            .collect())
    }

    async fn webauthn_get_credential_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<(Uuid, Passkey)>, Self::Error> {
        let passkeys = self.passkeys.read().await;

        Ok(passkeys.get(credential_id).cloned())
    }

    async fn webauthn_update_credential(
        &self,
        user_id: &Uuid,
        passkey: Passkey,
    ) -> Result<(), Self::Error> {
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

    async fn webauthn_delete_credential(
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
    async fn org_create(
        &self,
        name: &str,
        slug: &str,
        parent: Option<&Uuid>,
    ) -> Result<MyOrganization, Self::Error> {
        let mut orgs = self.orgs.write().await;

        if orgs.values().any(|o| o.slug == slug) {
            return Err(MemoryStoreError::SlugInUse(slug.to_string()));
        }

        let org = MyOrganization {
            id: Uuid::new_v4(),
            parent: parent.copied(),
            slug: slug.to_string(),
            name: name.to_string(),
            login_rules: OrgLoginRules::default(),
            role_inheritance: Vec::new(),
            privilege_inheritance: Vec::new(),
        };

        orgs.insert(org.id, org.clone());

        Ok(org)
    }

    async fn org_get(&self, org_id: &Uuid) -> Result<Option<MyOrganization>, Self::Error> {
        Ok(self.orgs.read().await.get(org_id).cloned())
    }

    async fn org_get_by_slug(&self, slug: &str) -> Result<Option<MyOrganization>, Self::Error> {
        Ok(self
            .orgs
            .read()
            .await
            .values()
            .find(|o| o.slug == slug)
            .cloned())
    }

    async fn org_get_children(&self, org_id: &Uuid) -> Result<Vec<MyOrganization>, Self::Error> {
        Ok(self
            .orgs
            .read()
            .await
            .values()
            .filter(|o| o.parent == Some(*org_id))
            .cloned()
            .collect())
    }

    async fn org_update(
        &self,
        org_id: &Uuid,
        name: &str,
        login_rules: OrgLoginRules,
        role_inheritance: Vec<(String, String)>,
        privilege_inheritance: Vec<(OrgPrivilege, OrgPrivilege)>,
    ) -> Result<(), Self::Error> {
        if let Some(org) = self.orgs.write().await.get_mut(org_id) {
            org.name = name.to_string();
            org.login_rules = login_rules;
            org.role_inheritance = role_inheritance;
            org.privilege_inheritance = privilege_inheritance;
        }

        Ok(())
    }

    async fn org_delete(&self, org_id: &Uuid) -> Result<(), Self::Error> {
        self.orgs.write().await.remove(org_id);
        self.org_members
            .write()
            .await
            .retain(|m| m.org_id != *org_id);
        self.org_oidc_providers
            .write()
            .await
            .retain(|p| p.org_id != *org_id);

        Ok(())
    }

    async fn org_upsert_member(
        &self,
        org_id: &Uuid,
        user_id: &Uuid,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
    ) -> Result<MyOrgMember, Self::Error> {
        let mut members = self.org_members.write().await;

        members.retain(|m| !(m.org_id == *org_id && m.user_id == *user_id));

        let member = MyOrgMember {
            user_id: *user_id,
            org_id: *org_id,
            privilege,
            roles,
        };

        members.push(member.clone());

        Ok(member)
    }

    async fn org_remove_member(&self, org_id: &Uuid, user_id: &Uuid) -> Result<(), Self::Error> {
        self.org_members
            .write()
            .await
            .retain(|m| !(m.org_id == *org_id && m.user_id == *user_id));

        Ok(())
    }

    async fn org_get_member(
        &self,
        org_id: &Uuid,
        user_id: &Uuid,
    ) -> Result<Option<MyOrgMember>, Self::Error> {
        Ok(self
            .org_members
            .read()
            .await
            .iter()
            .find(|m| m.org_id == *org_id && m.user_id == *user_id)
            .cloned())
    }

    async fn org_get_members(&self, org_id: &Uuid) -> Result<Vec<MyOrgMember>, Self::Error> {
        Ok(self
            .org_members
            .read()
            .await
            .iter()
            .filter(|m| m.org_id == *org_id)
            .cloned()
            .collect())
    }

    async fn org_get_user_memberships(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<MyOrgMember>, Self::Error> {
        Ok(self
            .org_members
            .read()
            .await
            .iter()
            .filter(|m| m.user_id == *user_id)
            .cloned()
            .collect())
    }

    async fn org_oidc_upsert(
        &self,
        org_id: &Uuid,
        config: NewOrgOidcProvider,
    ) -> Result<MyOrgOidcProvider, Self::Error> {
        let mut providers = self.org_oidc_providers.write().await;

        providers.retain(|p| !(p.org_id == *org_id && p.config.name == config.name));

        let provider = MyOrgOidcProvider {
            org_id: *org_id,
            config,
        };

        providers.push(provider.clone());

        Ok(provider)
    }

    async fn org_oidc_delete(&self, org_id: &Uuid, name: &str) -> Result<(), Self::Error> {
        self.org_oidc_providers
            .write()
            .await
            .retain(|p| !(p.org_id == *org_id && p.config.name == name));

        Ok(())
    }

    async fn org_oidc_get(
        &self,
        org_id: &Uuid,
        name: &str,
    ) -> Result<Option<MyOrgOidcProvider>, Self::Error> {
        Ok(self
            .org_oidc_providers
            .read()
            .await
            .iter()
            .find(|p| p.org_id == *org_id && p.config.name == name)
            .cloned())
    }

    async fn org_oidc_list(&self, org_id: &Uuid) -> Result<Vec<MyOrgOidcProvider>, Self::Error> {
        Ok(self
            .org_oidc_providers
            .read()
            .await
            .iter()
            .filter(|p| p.org_id == *org_id)
            .cloned()
            .collect())
    }


    async fn org_invite_create(
        &self,
        org_id: &Uuid,
        code: &str,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
        expires: DateTime<Utc>,
    ) -> Result<MyOrgInvite, Self::Error> {
        let invite = MyOrgInvite {
            org_id: *org_id,
            code: code.to_string(),
            privilege,
            roles,
            expires,
        };

        self.org_invites
            .write()
            .await
            .insert(code.to_string(), invite.clone());

        Ok(invite)
    }

    async fn org_invite_consume(&self, code: &str) -> Result<Option<MyOrgInvite>, Self::Error> {
        Ok(self.org_invites.write().await.remove(code))
    }

}
