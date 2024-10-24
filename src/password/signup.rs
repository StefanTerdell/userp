use crate::{
    config::Allow,
    core::CoreUserp,
    enums::LoginMethod,
    traits::{User, UserpCookies, UserpStore},
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
    StoreError(#[from] T),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
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

        let user = self
            .store
            .password_signup(
                password_id,
                password,
                self.pass.allow_login.as_ref().unwrap_or(&self.allow_signup) == &Allow::OnEither,
            )
            .await?;

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await?)
    }
}
