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
    Rejected(crate::password::PasswordRejected),
    #[error(transparent)]
    StoreError(#[from] T),
}

crate::ratelimit::impl_maybe_rate_limited!(PasswordSignupError, RateLimited);

impl<S: AutheryStore, C: AutheryCookies> CoreAuthery<S, C> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: &str,
        password: &str,
    ) -> Result<Self, PasswordSignupError<S::Error>> {
        if self.signup_allow(self.pass.allow_signup.as_ref()) == &Allow::Never {
            return Err(PasswordSignupError::NotAllowed);
        }

        self.check_rate(RateLimitOp::PasswordAttempt { password_id })
            .await
            .map_err(PasswordSignupError::RateLimited)?;

        let allow_login = self.login_allow(self.pass.allow_login.as_ref()) == &Allow::OnEither;

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
                    &self
                        .new_password_hash(password)
                        .await
                        .map_err(PasswordSignupError::Rejected)?,
                )
                .await?),
        }?;

        Ok(self.log_in(LoginMethod::Password, &user.get_id()).await?)
    }
}
