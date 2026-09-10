//! A minimal in-memory fixed-window rate limiter, as a demonstration of
//! authery's [`RateLimiter`] hook. Production apps likely want a store-backed
//! or redis-backed limiter, and an IP-keyed tower layer in front of the router.

use authery::prelude::*;
use authery::reexports::chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const WINDOW_MINUTES: i64 = 1;
const MAX_PASSWORD_ATTEMPTS: u32 = 5;
const MAX_EMAIL_SENDS: u32 = 3;
const MAX_OTP_ATTEMPTS: u32 = 5;

type Window = (DateTime<Utc>, u32);

#[derive(Debug, Default, Clone)]
pub struct FixedWindowRateLimiter {
    windows: Arc<Mutex<HashMap<String, Window>>>,
}

impl FixedWindowRateLimiter {
    fn hit(&self, key: String, max: u32) -> Result<(), RateLimited> {
        let now = Utc::now();
        let mut windows = self.windows.lock().unwrap();

        let (window_start, count) = windows.entry(key).or_insert((now, 0));

        if now - *window_start > Duration::minutes(WINDOW_MINUTES) {
            (*window_start, *count) = (now, 0);
        }

        *count += 1;

        if *count > max {
            Err(RateLimited {
                retry_after: Some(*window_start + Duration::minutes(WINDOW_MINUTES) - now),
            })
        } else {
            Ok(())
        }
    }
}

impl RateLimiter for FixedWindowRateLimiter {
    fn check<'a>(&'a self, op: RateLimitOp<'a>) -> RateLimitFuture<'a> {
        let result = match op {
            RateLimitOp::PasswordAttempt { password_id } => {
                self.hit(format!("pw:{password_id}"), MAX_PASSWORD_ATTEMPTS)
            }
            RateLimitOp::EmailSend { address } => {
                self.hit(format!("email:{address}"), MAX_EMAIL_SENDS)
            }
            RateLimitOp::OtpAttempt { address } => {
                self.hit(format!("otp:{address}"), MAX_OTP_ATTEMPTS)
            }
            _ => Ok(()),
        };

        Box::pin(async move { result })
    }
}
