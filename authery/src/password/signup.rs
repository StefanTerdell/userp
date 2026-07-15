use crate::{
    core::CoreAuthery,
    models::{User, AutheryCookies},
    store::AutheryStore,
};
use thiserror::Error;
use crate::models::{Allow, LoginMethod};

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

        let allow_login =
            self.pass.allow_login.as_ref().unwrap_or(&self.allow_signup) == &Allow::OnEither;

        let user = match self
            .store
            .password_get_user_by_password_id(password_id)
            .await?
        {
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
                .password_create_user(
                    password_id,
                    &self.pass.hasher.genereate_hash(password.into()).await,
                )
                .await?),
        }?;

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await?)
    }
}
