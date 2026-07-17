//! A complete [`AutheryStore`] over Postgres via sqlx.
//!
//! Worth noticing while reading:
//! - Multi-write methods (user + email + token creation) run in transactions.
//! - `consume_challenge` is a single `DELETE ... RETURNING` - fetch AND
//!   delete, so challenges are single-use even under concurrent requests.
//! - Deletes are scoped by user id in the WHERE clause, which is what the
//!   ownership contracts ask for.
//! - `LoginMethod`, `Passkey` and `TotpCredential` are persisted as opaque
//!   jsonb - the store never inspects them.

#[cfg(any(feature = "email", feature = "sms"))]
use crate::models::PgChallenge;
#[cfg(feature = "oauth")]
use crate::models::PgOAuthToken;
#[cfg(feature = "email")]
use crate::models::PgUserEmail;
#[cfg(feature = "sms")]
use crate::models::PgUserPhone;
use crate::models::{PgSession, PgUser};
#[cfg(feature = "webauthn")]
use authery::reexports::webauthn_rs::prelude::Passkey;
#[allow(unused_imports)]
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
#[allow(unused_imports)]
use sqlx::{PgPool, Row, types::Json};

#[derive(Clone, Debug)]
pub struct PgStore {
    pub pool: PgPool,
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(url).await?;
        sqlx::raw_sql(include_str!("../schema.sql"))
            .execute(&pool)
            .await?;
        Ok(Self { pool })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PgStoreError {
    #[error("The email address is already in use: {0}")]
    AddressInUse(String),
    #[error("The token was not found: {0}")]
    TokenNotFound(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

impl IntoResponse for PgStoreError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

impl AutheryStore for PgStore {
    type Error = PgStoreError;
    type UserId = Uuid;
    type SessionId = Uuid;
    #[cfg(feature = "oauth")]
    type OAuthTokenId = Uuid;
    type User = PgUser;
    #[cfg(feature = "email")]
    type UserEmail = PgUserEmail;
    #[cfg(feature = "sms")]
    type UserPhone = PgUserPhone;
    type LoginSession = PgSession;
    #[cfg(any(feature = "email", feature = "sms"))]
    type EmailChallenge = PgChallenge;
    #[cfg(feature = "oauth")]
    type OAuthToken = PgOAuthToken;

    // --- basic store ---

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<PgUser>, PgStoreError> {
        Ok(
            sqlx::query_as("SELECT id, password_hash FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    #[cfg(feature = "user")]
    async fn delete_user(&self, id: &Uuid) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_session(
        &self,
        user_id: &Uuid,
        method: LoginMethod,
        expires: DateTime<Utc>,
    ) -> Result<PgSession, PgStoreError> {
        Ok(sqlx::query_as(
            "INSERT INTO sessions (id, user_id, method, expires) VALUES ($1, $2, $3, $4)
             RETURNING id, user_id, method, expires",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(Json(method))
        .bind(expires)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn get_session(&self, session_id: &Uuid) -> Result<Option<PgSession>, PgStoreError> {
        Ok(
            sqlx::query_as("SELECT id, user_id, method, expires FROM sessions WHERE id = $1")
                .bind(session_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn delete_session(&self, user_id: &Uuid, session_id: &Uuid) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &Uuid) -> Result<Vec<PgSession>, PgStoreError> {
        Ok(
            sqlx::query_as("SELECT id, user_id, method, expires FROM sessions WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    // --- mfa store ---

    #[cfg(feature = "mfa")]
    async fn set_recovery_code_hashes(
        &self,
        user_id: &Uuid,
        hashes: Vec<String>,
    ) -> Result<(), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for hash in hashes {
            sqlx::query("INSERT INTO recovery_codes (user_id, hash) VALUES ($1, $2)")
                .bind(user_id)
                .bind(hash)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    #[cfg(feature = "mfa")]
    async fn consume_recovery_code_hash(
        &self,
        user_id: &Uuid,
        hash: &str,
    ) -> Result<bool, PgStoreError> {
        // Fetch AND delete in one statement: single-use under concurrency.
        Ok(sqlx::query(
            "DELETE FROM recovery_codes WHERE user_id = $1 AND hash = $2 RETURNING hash",
        )
        .bind(user_id)
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    #[cfg(feature = "mfa")]
    async fn count_recovery_codes(&self, user_id: &Uuid) -> Result<usize, PgStoreError> {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM recovery_codes WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count as usize)
    }

    // --- password store ---

    #[cfg(feature = "password")]
    async fn get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<PgUser>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT u.id, u.password_hash FROM users u
             JOIN user_emails e ON e.user_id = u.id
             WHERE e.address = $1",
        )
        .bind(password_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    #[cfg(feature = "password")]
    async fn create_user_by_password_id(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<PgUser, PgStoreError> {
        let mut tx = self.pool.begin().await?;

        let in_use: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_emails WHERE address = $1)")
                .bind(password_id)
                .fetch_one(&mut *tx)
                .await?;
        if in_use {
            return Err(PgStoreError::AddressInUse(password_id.to_string()));
        }

        let user: PgUser = sqlx::query_as(
            "INSERT INTO users (id, password_hash) VALUES ($1, $2) RETURNING id, password_hash",
        )
        .bind(Uuid::new_v4())
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO user_emails (user_id, address, verified, allow_link_login)
             VALUES ($1, $2, false, false)",
        )
        .bind(user.id)
        .bind(password_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(user)
    }

    #[cfg(all(feature = "user", feature = "password"))]
    async fn clear_user_password_hash(
        &self,
        user_id: &Uuid,
        session_id: &Uuid,
    ) -> Result<(), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        // Changing the password invalidates other password-borne sessions.
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND method = $2 AND id <> $3")
            .bind(user_id)
            .bind(Json(LoginMethod::Password))
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE users SET password_hash = NULL WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    #[cfg(all(any(feature = "user", feature = "email"), feature = "password"))]
    async fn set_user_password_hash(
        &self,
        user_id: &Uuid,
        password_hash: String,
        session_id: &Uuid,
    ) -> Result<(), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND method = $2 AND id <> $3")
            .bind(user_id)
            .bind(Json(LoginMethod::Password))
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(user_id)
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    // --- email store ---

    #[cfg(feature = "email")]
    async fn get_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<Option<(PgUser, PgUserEmail)>, PgStoreError> {
        let Some(email): Option<PgUserEmail> = sqlx::query_as(
            "SELECT user_id, address, verified, allow_link_login FROM user_emails
             WHERE address = $1",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        Ok(self.get_user(&email.user_id).await?.map(|u| (u, email)))
    }

    #[cfg(feature = "email")]
    async fn create_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<(PgUser, PgUserEmail), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        let in_use: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_emails WHERE address = $1)")
                .bind(address)
                .fetch_one(&mut *tx)
                .await?;
        if in_use {
            return Err(PgStoreError::AddressInUse(address.to_string()));
        }

        let user: PgUser =
            sqlx::query_as("INSERT INTO users (id) VALUES ($1) RETURNING id, password_hash")
                .bind(Uuid::new_v4())
                .fetch_one(&mut *tx)
                .await?;

        // The user just proved control of the address, so it starts verified.
        let email: PgUserEmail = sqlx::query_as(
            "INSERT INTO user_emails (user_id, address, verified, allow_link_login)
             VALUES ($1, $2, true, true)
             RETURNING user_id, address, verified, allow_link_login",
        )
        .bind(user.id)
        .bind(address)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((user, email))
    }

    #[cfg(feature = "email")]
    async fn set_email_verified(&self, address: &str) -> Result<(), PgStoreError> {
        sqlx::query("UPDATE user_emails SET verified = true WHERE address = $1")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[cfg(any(feature = "email", feature = "sms"))]
    async fn create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<PgChallenge, PgStoreError> {
        Ok(sqlx::query_as(
            "INSERT INTO challenges (code, address, next, expires) VALUES ($1, $2, $3, $4)
             RETURNING code, address, next, expires",
        )
        .bind(code)
        .bind(address)
        .bind(next)
        .bind(expires)
        .fetch_one(&self.pool)
        .await?)
    }

    #[cfg(any(feature = "email", feature = "sms"))]
    async fn consume_challenge(&self, code: String) -> Result<Option<PgChallenge>, PgStoreError> {
        // Fetch AND delete in one statement: single-use under concurrency.
        Ok(sqlx::query_as(
            "DELETE FROM challenges WHERE code = $1 RETURNING code, address, next, expires",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?)
    }

    #[cfg(feature = "email")]
    async fn get_user_emails(&self, user_id: &Uuid) -> Result<Vec<PgUserEmail>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT user_id, address, verified, allow_link_login FROM user_emails
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn set_user_email_allow_link_login(
        &self,
        user_id: &Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), PgStoreError> {
        sqlx::query(
            "UPDATE user_emails SET allow_link_login = $3 WHERE user_id = $1 AND address = $2",
        )
        .bind(user_id)
        .bind(address)
        .bind(allow_login)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn add_user_email(&self, user_id: &Uuid, address: String) -> Result<(), PgStoreError> {
        let taken: Option<Uuid> =
            sqlx::query_scalar("SELECT user_id FROM user_emails WHERE address = $1")
                .bind(&address)
                .fetch_optional(&self.pool)
                .await?;

        match taken {
            Some(owner) if owner == *user_id => Ok(()),
            Some(_) => Err(PgStoreError::AddressInUse(address)),
            None => {
                sqlx::query(
                    "INSERT INTO user_emails (user_id, address, verified, allow_link_login)
                     VALUES ($1, $2, false, false)",
                )
                .bind(user_id)
                .bind(address)
                .execute(&self.pool)
                .await?;
                Ok(())
            }
        }
    }

    #[cfg(all(feature = "user", feature = "email"))]
    async fn delete_user_email(&self, user_id: &Uuid, address: String) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM user_emails WHERE user_id = $1 AND address = $2")
            .bind(user_id)
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- sms store ---

    #[cfg(feature = "sms")]
    async fn get_user_by_phone(
        &self,
        number: &str,
    ) -> Result<Option<(PgUser, PgUserPhone)>, PgStoreError> {
        let Some(phone): Option<PgUserPhone> = sqlx::query_as(
            "SELECT user_id, number, verified, allow_login FROM user_phones WHERE number = $1",
        )
        .bind(number)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        Ok(self.get_user(&phone.user_id).await?.map(|u| (u, phone)))
    }

    #[cfg(feature = "sms")]
    async fn create_user_by_phone(
        &self,
        number: &str,
    ) -> Result<(PgUser, PgUserPhone), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        let user: PgUser =
            sqlx::query_as("INSERT INTO users (id) VALUES ($1) RETURNING id, password_hash")
                .bind(Uuid::new_v4())
                .fetch_one(&mut *tx)
                .await?;

        let phone: PgUserPhone = sqlx::query_as(
            "INSERT INTO user_phones (user_id, number, verified, allow_login)
             VALUES ($1, $2, true, true)
             RETURNING user_id, number, verified, allow_login",
        )
        .bind(user.id)
        .bind(number)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((user, phone))
    }

    #[cfg(feature = "sms")]
    async fn get_user_phones(&self, user_id: &Uuid) -> Result<Vec<PgUserPhone>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT user_id, number, verified, allow_login FROM user_phones WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    // --- totp store ---

    #[cfg(feature = "totp")]
    async fn get_totp(&self, user_id: &Uuid) -> Result<Option<TotpCredential>, PgStoreError> {
        Ok(
            sqlx::query("SELECT credential FROM totp_credentials WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?
                .map(|row| row.get::<Json<TotpCredential>, _>("credential").0),
        )
    }

    #[cfg(feature = "totp")]
    async fn upsert_totp(
        &self,
        user_id: &Uuid,
        credential: TotpCredential,
    ) -> Result<(), PgStoreError> {
        sqlx::query(
            "INSERT INTO totp_credentials (user_id, credential) VALUES ($1, $2)
             ON CONFLICT (user_id) DO UPDATE SET credential = EXCLUDED.credential",
        )
        .bind(user_id)
        .bind(Json(credential))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "totp")]
    async fn delete_totp(&self, user_id: &Uuid) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM totp_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- webauthn store ---

    #[cfg(feature = "webauthn")]
    async fn create_passkey(&self, user_id: &Uuid, passkey: Passkey) -> Result<(), PgStoreError> {
        sqlx::query(
            "INSERT INTO passkeys (credential_id, user_id, passkey) VALUES ($1, $2, $3)
             ON CONFLICT (credential_id) DO UPDATE SET passkey = EXCLUDED.passkey",
        )
        .bind(passkey.cred_id().as_slice())
        .bind(user_id)
        .bind(Json(&passkey))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[cfg(feature = "webauthn")]
    async fn get_passkeys(&self, user_id: &Uuid) -> Result<Vec<Passkey>, PgStoreError> {
        Ok(
            sqlx::query("SELECT passkey FROM passkeys WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|row| row.get::<Json<Passkey>, _>("passkey").0)
                .collect(),
        )
    }

    #[cfg(feature = "webauthn")]
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<(Uuid, Passkey)>, PgStoreError> {
        Ok(
            sqlx::query("SELECT user_id, passkey FROM passkeys WHERE credential_id = $1")
                .bind(credential_id)
                .fetch_optional(&self.pool)
                .await?
                .map(|row| {
                    (
                        row.get::<Uuid, _>("user_id"),
                        row.get::<Json<Passkey>, _>("passkey").0,
                    )
                }),
        )
    }

    #[cfg(feature = "webauthn")]
    async fn update_passkey(&self, user_id: &Uuid, passkey: Passkey) -> Result<(), PgStoreError> {
        sqlx::query("UPDATE passkeys SET passkey = $3 WHERE credential_id = $1 AND user_id = $2")
            .bind(passkey.cred_id().as_slice())
            .bind(user_id)
            .bind(Json(&passkey))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[cfg(all(feature = "webauthn", feature = "user"))]
    async fn delete_passkey(
        &self,
        user_id: &Uuid,
        credential_id: &[u8],
    ) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM passkeys WHERE credential_id = $1 AND user_id = $2")
            .bind(credential_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- oauth store ---

    #[cfg(feature = "oauth")]
    async fn get_oauth_token_by_id(
        &self,
        token_id: &Uuid,
    ) -> Result<Option<PgOAuthToken>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                    expires, scopes
             FROM oauth_tokens WHERE id = $1",
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    #[cfg(all(feature = "user", feature = "oauth"))]
    async fn get_user_oauth_tokens(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<PgOAuthToken>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                    expires, scopes
             FROM oauth_tokens WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    #[cfg(all(feature = "user", feature = "oauth"))]
    async fn delete_oauth_token(
        &self,
        user_id: &Uuid,
        token_id: &Uuid,
    ) -> Result<(), PgStoreError> {
        sqlx::query("DELETE FROM oauth_tokens WHERE id = $1 AND user_id = $2")
            .bind(token_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[cfg(feature = "oauth")]
    async fn update_token_by_unmatched_token(
        &self,
        token_id: &Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<PgOAuthToken, PgStoreError> {
        sqlx::query_as(
            "UPDATE oauth_tokens
             SET provider_name = $2, provider_user_id = $3, access_token = $4,
                 refresh_token = $5, expires = $6, scopes = $7
             WHERE id = $1
             RETURNING id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                       expires, scopes",
        )
        .bind(token_id)
        .bind(&unmatched_token.provider_name)
        .bind(&unmatched_token.provider_user_id)
        .bind(&unmatched_token.access_token)
        .bind(&unmatched_token.refresh_token)
        .bind(unmatched_token.expires)
        .bind(&unmatched_token.scopes)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PgStoreError::TokenNotFound(token_id.to_string()))
    }

    #[cfg(feature = "oauth")]
    async fn get_token_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<PgOAuthToken>, PgStoreError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                    expires, scopes
             FROM oauth_tokens WHERE provider_name = $1 AND provider_user_id = $2",
        )
        .bind(&unmatched_token.provider_name)
        .bind(&unmatched_token.provider_user_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    #[cfg(feature = "oauth")]
    async fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<(PgUser, PgOAuthToken)>, PgStoreError> {
        let Some(token) = self
            .get_token_by_unmatched_token(unmatched_token.clone())
            .await?
        else {
            return Ok(None);
        };

        Ok(self.get_user(&token.user_id).await?.map(|u| (u, token)))
    }

    #[cfg(feature = "oauth")]
    async fn create_user_token_from_unmatched_token(
        &self,
        user_id: &Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<PgOAuthToken, PgStoreError> {
        let mut tx = self.pool.begin().await?;

        // The provider vouches for an email? Attach it, unverified.
        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            sqlx::query(
                "INSERT INTO user_emails (user_id, address, verified, allow_link_login)
                 VALUES ($1, $2, false, false)
                 ON CONFLICT (address) DO NOTHING",
            )
            .bind(user_id)
            .bind(address)
            .execute(&mut *tx)
            .await?;
        }

        let token: PgOAuthToken = sqlx::query_as(
            "INSERT INTO oauth_tokens (id, user_id, provider_name, provider_user_id, access_token,
                                       refresh_token, expires, scopes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                       expires, scopes",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(&unmatched_token.provider_name)
        .bind(&unmatched_token.provider_user_id)
        .bind(&unmatched_token.access_token)
        .bind(&unmatched_token.refresh_token)
        .bind(unmatched_token.expires)
        .bind(&unmatched_token.scopes)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(token)
    }

    #[cfg(feature = "oauth")]
    async fn create_user_from_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<(PgUser, PgOAuthToken), PgStoreError> {
        let mut tx = self.pool.begin().await?;

        let user: PgUser =
            sqlx::query_as("INSERT INTO users (id) VALUES ($1) RETURNING id, password_hash")
                .bind(Uuid::new_v4())
                .fetch_one(&mut *tx)
                .await?;

        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            let in_use: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_emails WHERE address = $1)")
                    .bind(address)
                    .fetch_one(&mut *tx)
                    .await?;
            if in_use {
                return Err(PgStoreError::AddressInUse(address.to_string()));
            }

            sqlx::query(
                "INSERT INTO user_emails (user_id, address, verified, allow_link_login)
                 VALUES ($1, $2, false, false)",
            )
            .bind(user.id)
            .bind(address)
            .execute(&mut *tx)
            .await?;
        }

        let token: PgOAuthToken = sqlx::query_as(
            "INSERT INTO oauth_tokens (id, user_id, provider_name, provider_user_id, access_token,
                                       refresh_token, expires, scopes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, user_id, provider_name, provider_user_id, access_token, refresh_token,
                       expires, scopes",
        )
        .bind(Uuid::new_v4())
        .bind(user.id)
        .bind(&unmatched_token.provider_name)
        .bind(&unmatched_token.provider_user_id)
        .bind(&unmatched_token.access_token)
        .bind(&unmatched_token.refresh_token)
        .bind(unmatched_token.expires)
        .bind(&unmatched_token.scopes)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((user, token))
    }
}
