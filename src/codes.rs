//! Pluggable one-time-code generation for the `otp` and `sms` features (and
//! their MFA factors). The default is [`NumericCode`] - six digits, what
//! every authenticator UX expects. Codes are opaque strings all the way
//! through authery, so a custom generator can emit any shape it likes; the
//! bundled code-entry pages adapt through the generator's
//! [`html_input_mode`](CodeGenerator::html_input_mode) and
//! [`code_length`](CodeGenerator::code_length) hints.
//!
//! Note that no human-typeable code survives brute force without throttling:
//! codes are single-use and short-lived, but the load-bearing control is
//! your [`RateLimiter`](crate::ratelimit::RateLimiter). A longer code is a
//! policy choice, not a substitute.

use uuid::Uuid;

/// Generates the one-time codes sent by email (`otp`) and text (`sms`).
///
/// Implementations MUST use a cryptographically secure randomness source.
/// Verification is an exact string match, so implementers of alphanumeric
/// codes own their case handling (generate one case, accept it verbatim) and
/// would do well to avoid ambiguous characters (`0`/`O`, `1`/`l`).
pub trait CodeGenerator: Send + Sync + std::fmt::Debug {
    /// Generate a fresh code.
    fn generate(&self) -> String;

    /// The [`inputmode`](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/inputmode)
    /// the bundled code-entry inputs should use, e.g. `numeric`. `None` (the
    /// default) renders a plain text input.
    fn html_input_mode(&self) -> Option<&str> {
        None
    }

    /// The exact code length, when fixed. Drives `maxlength` (and, for
    /// numeric input modes, the validation `pattern`) on the bundled
    /// code-entry inputs. `None` (the default) leaves the input unbounded.
    fn code_length(&self) -> Option<u8> {
        None
    }
}

/// The default generator: `n` decimal digits (zero-padded) from the CSPRNG
/// behind UUIDv4. The modulo bias on 122 random bits is negligible for any
/// sane length. Lengths are clamped to `1..=30`.
#[derive(Debug, Clone, Copy)]
pub struct NumericCode(pub u8);

impl NumericCode {
    pub fn new(digits: u8) -> Self {
        Self(digits.clamp(1, 30))
    }
}

impl Default for NumericCode {
    fn default() -> Self {
        Self(6)
    }
}

impl CodeGenerator for NumericCode {
    fn generate(&self) -> String {
        let digits = self.0.clamp(1, 30) as u32;
        let code = Uuid::new_v4().as_u128() % 10u128.pow(digits);
        format!("{code:0width$}", width = digits as usize)
    }

    fn html_input_mode(&self) -> Option<&str> {
        Some("numeric")
    }

    fn code_length(&self) -> Option<u8> {
        Some(self.0.clamp(1, 30))
    }
}
