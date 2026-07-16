//! Integration tests for the core auth flows, run with:
//!   cargo test -p authery --no-default-features --features password,email,otp,mfa,user
#![cfg(all(
    feature = "password",
    feature = "email",
    feature = "otp",
    feature = "mfa",
    feature = "user"
))]

mod common;

use authery::mfa::MfaPolicy;
use authery::models::{LoginMethod, LoginMethodRules, LoginSession};
use authery::password::login::PasswordLoginError;
use authery::ratelimit::{RateLimitFuture, RateLimitOp, RateLimited, RateLimiter};
use authery::reexports::chrono::Duration;
use common::{auth, AuthBuilder, TestStore};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn password_login_happy_path() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", Some("hunter2"));

    let logged_in = auth(&store)
        .password_login("alice@x.com", "hunter2")
        .await
        .unwrap();

    let session = logged_in.session().await.unwrap().expect("logged in");
    assert_eq!(session.get_user_id(), user_id);
    assert_eq!(session.get_method(), LoginMethod::Password);
}

/// Wrong password and unknown user must be indistinguishable to the caller.
#[tokio::test]
async fn password_login_does_not_reveal_user_existence() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2"));

    let wrong_password = auth(&store)
        .password_login("alice@x.com", "nope")
        .await
        .unwrap_err();
    let unknown_user = auth(&store)
        .password_login("nobody@x.com", "nope")
        .await
        .unwrap_err();

    assert!(matches!(wrong_password, PasswordLoginError::WrongPassword));
    assert!(matches!(unknown_user, PasswordLoginError::WrongPassword));
    assert_eq!(wrong_password.to_string(), unknown_user.to_string());
}

#[tokio::test]
async fn expired_sessions_are_logged_out_and_evicted() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", Some("hunter2"));

    let mut builder = AuthBuilder::new(store.clone());
    builder.session_lifetime = Duration::seconds(-1); // born expired
    let logged_in = builder
        .build()
        .password_login("alice@x.com", "hunter2")
        .await
        .unwrap();

    assert!(logged_in.session().await.unwrap().is_none());
    assert_eq!(store.session_count(user_id), 0, "evicted from the store");
}

#[tokio::test]
async fn session_cap_evicts_oldest() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", Some("hunter2"));

    for _ in 0..3 {
        let mut builder = AuthBuilder::new(store.clone());
        builder.max_concurrent_sessions = Some(2);
        builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
    }

    assert_eq!(store.session_count(user_id), 2);
}

#[derive(Debug)]
struct CountingLimiter {
    attempts: AtomicU32,
    max: u32,
}

impl RateLimiter for CountingLimiter {
    fn check<'a>(&'a self, op: RateLimitOp<'a>) -> RateLimitFuture<'a> {
        let allowed = match op {
            RateLimitOp::PasswordAttempt { .. } => {
                self.attempts.fetch_add(1, Ordering::SeqCst) < self.max
            }
            _ => true,
        };
        Box::pin(async move {
            if allowed {
                Ok(())
            } else {
                Err(RateLimited { retry_after: None })
            }
        })
    }
}

#[tokio::test]
async fn rate_limiter_blocks_password_attempts() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", Some("hunter2"));

    let limiter = Arc::new(CountingLimiter {
        attempts: AtomicU32::new(0),
        max: 2,
    });

    for attempt in 0..3 {
        let mut builder = AuthBuilder::new(store.clone());
        builder.rate_limiter = limiter.clone();
        let result = builder.build().password_login("alice@x.com", "wrong").await;

        if attempt < 2 {
            assert!(matches!(result, Err(PasswordLoginError::WrongPassword)));
        } else {
            assert!(matches!(result, Err(PasswordLoginError::RateLimited(_))));
        }
    }
}

#[tokio::test]
async fn otp_verify_is_single_use_and_code_checked() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", None);

    // Stand in for the emailed code (init would SMTP it): the store key is
    // namespaced per address.
    store.seed_challenge("otp:alice@x.com:123456", "alice@x.com", Duration::minutes(5));

    let err = auth(&store)
        .otp_login_verify("alice@x.com", "999999")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Wrong or expired code");

    let (logged_in, _next) = auth(&store)
        .otp_login_verify("alice@x.com", "123456")
        .await
        .unwrap();
    let session = logged_in.session().await.unwrap().expect("logged in");
    assert_eq!(session.get_user_id(), user_id);

    // Single use: the same code is gone.
    let replay = auth(&store)
        .otp_login_verify("alice@x.com", "123456")
        .await
        .unwrap_err();
    assert_eq!(replay.to_string(), "Wrong or expired code");
}

#[tokio::test]
async fn otp_verify_rejects_expired_codes() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", None);
    store.seed_challenge("otp:alice@x.com:123456", "alice@x.com", Duration::seconds(-1));

    let err = auth(&store)
        .otp_login_verify("alice@x.com", "123456")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Wrong or expired code");
}

/// A code issued for one address must not work for another (the store key is
/// address-namespaced).
#[tokio::test]
async fn otp_codes_are_bound_to_their_address() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", None);
    store.seed_user("bob@x.com", None);
    store.seed_challenge("otp:alice@x.com:123456", "alice@x.com", Duration::minutes(5));

    let err = auth(&store)
        .otp_login_verify("bob@x.com", "123456")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Wrong or expired code");
}

fn mfa_for_password() -> MfaPolicy {
    MfaPolicy {
        require_for_password: true,
        require_for_email: false,
        require_for_otp: false,
    }
}

#[tokio::test]
async fn mfa_policy_creates_pending_session_and_otp_upgrades_it() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", Some("hunter2"));

    // The user has a verified email, so a second factor is available and the
    // password login must be downgraded to a pending session.
    let mut builder = AuthBuilder::new(store.clone());
    builder.mfa_policy = mfa_for_password();
    let pending = builder
        .build()
        .password_login("alice@x.com", "hunter2")
        .await
        .unwrap();

    assert!(
        pending.session().await.unwrap().is_none(),
        "pending sessions are not logged in"
    );
    let pending_session = pending
        .mfa_pending_session()
        .await
        .unwrap()
        .expect("a pending session exists");
    assert!(matches!(
        pending_session.get_method(),
        LoginMethod::MfaPending { .. }
    ));

    // Complete the second factor with a directly-seeded code.
    store.seed_challenge("mfa:alice@x.com:654321", "alice@x.com", Duration::minutes(5));
    let upgraded = pending.mfa_otp_verify("654321").await.unwrap();

    let session = upgraded.session().await.unwrap().expect("now logged in");
    assert_eq!(session.get_user_id(), user_id);
    let LoginMethod::Mfa { first, second } = session.get_method() else {
        panic!("expected an Mfa session, got {}", session.get_method());
    };
    assert_eq!(*first, LoginMethod::Password);
    assert!(matches!(*second, LoginMethod::Otp { .. }));

    // The pending session was replaced, not kept alongside.
    assert_eq!(store.session_count(user_id), 1);
}

#[tokio::test]
async fn mfa_policy_skips_users_without_a_second_factor() {
    let store = TestStore::default();

    // Signup creates an unverified address: no usable second factor.
    let mut builder = AuthBuilder::new(store.clone());
    builder.mfa_policy = mfa_for_password();
    let logged_in = builder
        .build()
        .password_signup("fresh@x.com", "hunter2")
        .await
        .unwrap();

    assert!(
        logged_in.session().await.unwrap().is_some(),
        "no factor registered, so the login completes normally"
    );
}

#[test]
fn login_method_rules_judge_first_factor_and_mfa() {
    let mfa_required = LoginMethodRules {
        require_mfa: true,
        ..Default::default()
    };
    let password = LoginMethod::Password;
    let mfa_password_otp = LoginMethod::Mfa {
        first: Box::new(LoginMethod::Password),
        second: Box::new(LoginMethod::Otp {
            address: "a@x.com".into(),
        }),
    };

    assert!(!mfa_required.satisfies(&password));
    assert!(mfa_required.satisfies(&mfa_password_otp));

    let no_password = LoginMethodRules {
        allow_password: false,
        ..Default::default()
    };
    assert!(!no_password.satisfies(&password));
    assert!(
        !no_password.satisfies(&mfa_password_otp),
        "the first factor is judged even inside an Mfa session"
    );
    assert!(no_password.satisfies(&LoginMethod::Email {
        address: "a@x.com".into()
    }));
}
