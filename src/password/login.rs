use crate::models::{Allow, LoginMethod};
use crate::ratelimit::{RateLimitOp, RateLimited};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, User},
    store::AutheryStore,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordLoginError<T: std::error::Error> {
    #[error("Password login not allowed")]
    NotAllowed,
    #[error("Wrong email or password")]
    WrongPassword,
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    StoreError(#[from] T),
}

crate::ratelimit::impl_maybe_rate_limited!(PasswordLoginError, RateLimited);

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_login(
        self,
        password_id: &str,
        password: &str,
    ) -> Result<Self, PasswordLoginError<S::Error>> {
        if self.pass.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(PasswordLoginError::NotAllowed);
        };

        self.check_rate(RateLimitOp::PasswordAttempt { password_id })
            .await
            .map_err(PasswordLoginError::RateLimited)?;

        let allow_signup = self
            .pass
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::OnEither;

        let user = match self.store.get_user_by_password_id(password_id).await? {
            Some(user) => match user.get_password_hash() {
                Some(hash) => {
                    if self
                        .pass
                        .hasher
                        .verify_password(password.into(), hash)
                        .await
                    {
                        Ok(user)
                    } else {
                        Err(PasswordLoginError::WrongPassword)
                    }
                }
                None => {
                    // Burn comparable time so missing passwords aren't detectable.
                    self.pass.hasher.generate_hash(password.to_string()).await;
                    Err(PasswordLoginError::WrongPassword)
                }
            },
            None if allow_signup => Ok(self
                .store
                .create_user_by_password_id(
                    password_id,
                    &self.pass.hasher.generate_hash(password.to_string()).await,
                )
                .await?),
            None => {
                // Burn comparable time so unknown users aren't detectable.
                self.pass.hasher.generate_hash(password.to_string()).await;
                Err(PasswordLoginError::WrongPassword)
            }
        };

        let user = match user {
            Ok(user) => user,
            Err(err) => {
                if matches!(err, PasswordLoginError::WrongPassword) {
                    self.emit(crate::events::AuthEvent::PasswordRejected {
                        password_id: password_id.to_string(),
                    });
                }
                return Err(err);
            }
        };

        Ok(self.log_in(LoginMethod::Password, &user.get_id()).await?)
    }
}
