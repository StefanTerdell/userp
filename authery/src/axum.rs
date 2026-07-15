pub mod cookies;
pub mod extract;
pub mod router;

use crate::core::CoreAuthery;
use cookies::AxumAutheryCookies;

pub type AxumAuthery<S> = CoreAuthery<S, AxumAutheryCookies>;
