use crate::models::{Allow, LoginMethod};
use crate::ratelimit::{RateLimitOp, RateLimited};
use crate::{
    core::CoreAuthery,
    models::{AutheryCookies, User},
    store::AutheryStore,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasswordSignupError<T: std::error::Error> {
    #[error("Password signup not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error("Wrong login password")]
    WrongPassword,
    #[error(transparent)]
    RateLimited(RateLimited),
    #[error(transparent)]
    StoreError(#[from] T),
}

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: &str,
        password: &str,
    ) -> Result<Self, PasswordSignupError<S::Error>> {
        if self
            .pass
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(PasswordSignupError::NotAllowed);
        }

        self.rate_limiter
            .check(RateLimitOp::PasswordAttempt { password_id })
            .await
            .map_err(PasswordSignupError::RateLimited)?;

        let allow_login =
            self.pass.allow_login.as_ref().unwrap_or(&self.allow_signup) == &Allow::OnEither;

        let user = match self.store.get_user_by_password_id(password_id).await? {
            Some(user) if allow_login => match user.get_password_hash() {
                Some(hash) => {
                    if self
                        .pass
                        .hasher
                        .verify_password(password.into(), hash)
                        .await
                    {
                        Ok(user)
                    } else {
                        Err(PasswordSignupError::WrongPassword)
                    }
                }
                None => Err(PasswordSignupError::NotAllowed),
            },
            Some(_) => Err(PasswordSignupError::UserExists),
            None => Ok(self
                .store
                .create_user_by_password_id(
                    password_id,
                    &self.pass.hasher.generate_hash(password.into()).await,
                )
                .await?),
        }?;

        Ok(self.log_in(LoginMethod::Password, &user.get_id()).await?)
    }
}
