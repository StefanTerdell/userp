#[cfg(feature = "account")]
pub use crate::router::account::*;
#[cfg(feature = "email")]
pub use crate::router::email::*;
#[cfg(feature = "oauth-callbacks")]
pub use crate::router::oauth::*;
#[cfg(feature = "pages")]
pub use crate::router::pages::*;
#[cfg(feature = "password")]
pub use crate::router::password::*;
pub use crate::router::AxumRouter;