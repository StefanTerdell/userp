//! Integration tests for the core auth flows, run with:
//!   cargo test -p authery --no-default-features --features password,email,mfa,user
#![cfg(all(
    feature = "password",
    feature = "email",
    feature = "mfa",
    feature = "user"
))]

mod common;

use authery::mfa::MfaPolicy;
use authery::models::{LoginMethod, LoginMethodRules, LoginSession};
use authery::password::login::PasswordLoginError;
use authery::ratelimit::{RateLimitFuture, RateLimitOp, RateLimited, RateLimiter};
use authery::reexports::chrono::{Duration, Utc};
use common::{AuthBuilder, TestStore, auth};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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

/// With an idle timeout, unused sessions die before their absolute expiry,
/// and active ones get their last-seen refreshed (throttled).
#[tokio::test]
async fn idle_timeout_evicts_and_touches() {
    let store = TestStore::default();
    let user_id = store.seed_user("alice@x.com", Some("hunter2"));

    let mut builder = AuthBuilder::new(store.clone());
    builder.idle_timeout = Some(Duration::hours(1));
    let logged_in = builder
        .build()
        .password_login("alice@x.com", "hunter2")
        .await
        .unwrap();

    let session_id = logged_in.session().await.unwrap().expect("fresh").get_id();

    // 5 minutes idle: still logged in, and the touch refreshes last_seen.
    let stale = Utc::now() - Duration::minutes(5);
    store
        .sessions
        .lock()
        .unwrap()
        .get_mut(&session_id)
        .unwrap()
        .last_seen = Some(stale);
    assert!(logged_in.session().await.unwrap().is_some());
    let touched = store.sessions.lock().unwrap()[&session_id].last_seen;
    assert!(touched.unwrap() > stale, "touch refreshed last_seen");

    // 2 hours idle: logged out and evicted.
    store
        .sessions
        .lock()
        .unwrap()
        .get_mut(&session_id)
        .unwrap()
        .last_seen = Some(Utc::now() - Duration::hours(2));
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
    store.seed_challenge(
        "otp:alice@x.com:123456",
        "alice@x.com",
        Duration::minutes(5),
    );

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

/// Links and codes are one feature, two mechanisms - each can be withheld
/// by configuration alone.
#[tokio::test]
async fn email_mechanisms_can_be_withheld_by_config() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", None);
    store.seed_challenge(
        "otp:alice@x.com:123456",
        "alice@x.com",
        Duration::minutes(5),
    );

    let mut no_otp = auth(&store);
    no_otp.email.offer_otp = false;
    let err = no_otp
        .otp_login_verify("alice@x.com", "123456")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Otp login not allowed");

    let mut no_links = auth(&store);
    no_links.email.offer_links = false;
    let err = no_links
        .email_login_init("alice@x.com".into(), None)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Login not allowed");

    // The challenge is still there: only configuration said no.
    let (logged_in, _next) = auth(&store)
        .otp_login_verify("alice@x.com", "123456")
        .await
        .unwrap();
    assert!(logged_in.session().await.unwrap().is_some());
}

#[tokio::test]
async fn otp_verify_rejects_expired_codes() {
    let store = TestStore::default();
    store.seed_user("alice@x.com", None);
    store.seed_challenge(
        "otp:alice@x.com:123456",
        "alice@x.com",
        Duration::seconds(-1),
    );

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
    store.seed_challenge(
        "otp:alice@x.com:123456",
        "alice@x.com",
        Duration::minutes(5),
    );

    let err = auth(&store)
        .otp_login_verify("bob@x.com", "123456")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Wrong or expired code");
}

fn mfa_for_password() -> MfaPolicy {
    MfaPolicy {
        require_for_password: true,
        ..Default::default()
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
    store.seed_challenge(
        "mfa:alice@x.com:654321",
        "alice@x.com",
        Duration::minutes(5),
    );
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

#[cfg(feature = "sms")]
mod sms_tests {
    use super::*;
    use authery::events::{AuthEvent, DeliveryChannel};
    use authery::sms::SmsVerifyError;
    use common::CapturingEvents;

    /// Gateway errors reach the event hook, not the user-facing message.
    #[tokio::test]
    async fn sms_gateway_errors_are_generic_to_the_user_and_reported_to_the_hook() {
        let store = TestStore::default();
        let user_id = store.seed_user("alice@x.com", Some("hunter2"));
        store.seed_phone(user_id, "+46701234567");

        let mut builder = AuthBuilder::new(store.clone());
        let events = CapturingEvents::default();
        builder.events = Arc::new(events.clone());
        *builder.sms_sender.fail_with.lock().unwrap() =
            Some("401 Unauthorized: bad api key sk_live_123".into());

        let err = builder
            .build()
            .sms_login_init("+46701234567".into(), None)
            .await
            .unwrap_err();

        let user_facing = err.to_string();
        assert_eq!(
            user_facing,
            "Could not send the text message, please try again later"
        );
        assert!(!user_facing.contains("sk_live"), "gateway error leaked");

        let events = events.events.lock().unwrap();
        let delivery = events
            .iter()
            .find_map(|e| match e {
                AuthEvent::DeliveryFailed {
                    channel,
                    recipient,
                    error,
                } => Some((*channel, recipient.clone(), error.clone())),
                _ => None,
            })
            .expect("DeliveryFailed event emitted");
        assert_eq!(delivery.0, DeliveryChannel::Sms);
        assert_eq!(delivery.1, "+46701234567");
        assert!(
            delivery.2.contains("sk_live_123"),
            "hook sees the real error"
        );
    }

    /// Init texts a code through the sender, verify logs the user in. The
    /// code is single-use.
    #[tokio::test]
    async fn sms_login_init_and_verify() {
        let store = TestStore::default();
        let user_id = store.seed_user("alice@x.com", Some("hunter2"));
        store.seed_phone(user_id, "+46701234567");

        let builder = AuthBuilder::new(store.clone());
        let sender = builder.sms_sender.clone();
        let authery = builder.build();

        authery
            .sms_login_init("+46701234567".into(), None)
            .await
            .unwrap();
        let (to, message) = sender.sent.lock().unwrap().last().cloned().unwrap();
        assert_eq!(to, "+46701234567");
        assert!(message.contains("login code"));

        let code = sender.last_code();
        let (logged_in, _next) = authery
            .sms_login_verify("+46701234567", &code)
            .await
            .unwrap();
        let session = logged_in.session().await.unwrap().expect("logged in");
        assert_eq!(session.get_user_id(), user_id);
        assert_eq!(
            session.get_method(),
            LoginMethod::Sms {
                number: "+46701234567".into()
            }
        );

        // Consumed: the same code must not work again.
        let replay = auth(&store)
            .sms_login_verify("+46701234567", &code)
            .await
            .unwrap_err();
        assert!(matches!(replay, SmsVerifyError::WrongCode));
    }

    /// Signup on a fresh number creates the user; wrong codes and other
    /// numbers' codes are rejected.
    #[tokio::test]
    async fn sms_signup_creates_user_and_rejects_wrong_codes() {
        let store = TestStore::default();
        let builder = AuthBuilder::new(store.clone());
        let sender = builder.sms_sender.clone();
        let authery = builder.build();

        authery
            .sms_signup_init("+46700000001".into(), None)
            .await
            .unwrap();
        let code = sender.last_code();

        // A guessed code and the right code against another number both fail.
        let wrong = auth(&store)
            .sms_signup_verify("+46700000001", "000000")
            .await
            .unwrap_err();
        assert!(matches!(wrong, SmsVerifyError::WrongCode));
        let cross = auth(&store)
            .sms_signup_verify("+46700000002", &code)
            .await
            .unwrap_err();
        assert!(matches!(cross, SmsVerifyError::WrongCode));

        let (logged_in, _next) = authery
            .sms_signup_verify("+46700000001", &code)
            .await
            .unwrap();
        let session = logged_in.session().await.unwrap().expect("signed up");
        let user_id = session.get_user_id();
        assert!(store.users.lock().unwrap().contains_key(&user_id));
        assert_eq!(
            store.phones.lock().unwrap()[0].number,
            "+46700000001".to_string()
        );
    }

    /// A verified phone is a second factor: with the policy requiring MFA
    /// for passwords, login pends until the texted code is verified.
    #[tokio::test]
    async fn mfa_sms_factor_upgrades_pending_session() {
        let store = TestStore::default();

        // Signup creates an UNVERIFIED email, so the phone is the user's
        // only second factor.
        let signed_up = auth(&store)
            .password_signup("alice@x.com", "hunter2")
            .await
            .unwrap();
        let user_id = signed_up
            .session()
            .await
            .unwrap()
            .expect("signed up")
            .get_user_id();
        store.seed_phone(user_id, "+46701234567");

        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let _sender = builder.sms_sender.clone();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        assert!(pending.session().await.unwrap().is_none(), "pending");

        // The factor discovery offers the number, init texts it a code.
        let factors = pending
            .mfa_factors(&user_id, &LoginMethod::Password)
            .await
            .unwrap();
        assert_eq!(factors.sms_number.as_deref(), Some("+46701234567"));
        let number = pending.mfa_sms_init().await.unwrap();
        assert_eq!(number, "+46701234567");

        // A wrong code is rejected (and consumes the pending handle)...
        assert!(pending.mfa_sms_verify("000000").await.is_err());

        // ...so log in again: the texted code completes the fresh attempt.
        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let sender = builder.sms_sender.clone();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        pending.mfa_sms_init().await.unwrap();
        let upgraded = pending.mfa_sms_verify(&sender.last_code()).await.unwrap();
        let session = upgraded.session().await.unwrap().expect("logged in");
        let LoginMethod::Mfa { first, second } = session.get_method() else {
            panic!("expected Mfa session");
        };
        assert_eq!(*first, LoginMethod::Password);
        assert_eq!(
            *second,
            LoginMethod::Sms {
                number: "+46701234567".into()
            }
        );
    }
}

mod recovery_tests {
    use super::*;
    use authery::mfa::MfaRecoveryError;

    /// Generate a batch while logged in, then complete an MFA login with one
    /// of the codes. Codes are single-use and a new batch replaces the old.
    #[tokio::test]
    async fn recovery_codes_generate_and_upgrade_pending_session() {
        let store = TestStore::default();

        // Password signup: unverified email, so recovery codes will be the
        // user's only second factor.
        let logged_in = auth(&store)
            .password_signup("alice@x.com", "hunter2")
            .await
            .unwrap();
        let codes = logged_in.recovery_codes_generate().await.unwrap();
        assert_eq!(codes.len(), 10);
        assert_eq!(logged_in.recovery_codes_count().await.unwrap(), 10);

        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        assert!(pending.session().await.unwrap().is_none(), "pending");

        // A wrong code is rejected...
        assert!(matches!(
            pending.mfa_recovery_verify("nope-nope").await,
            Err(MfaRecoveryError::WrongCode)
        ));

        // ...the real one (typed messily: case and dashes are normalized)
        // completes the login.
        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        let messy = codes[0].to_uppercase().replace('-', " ");
        let upgraded = pending.mfa_recovery_verify(&messy).await.unwrap();
        let session = upgraded.session().await.unwrap().expect("logged in");
        let LoginMethod::Mfa { first, second } = session.get_method() else {
            panic!("expected Mfa session");
        };
        assert_eq!(*first, LoginMethod::Password);
        assert_eq!(*second, LoginMethod::RecoveryCode);
        assert_eq!(upgraded.recovery_codes_count().await.unwrap(), 9);

        // The consumed code must not work again.
        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        assert!(matches!(
            pending.mfa_recovery_verify(&codes[0]).await,
            Err(MfaRecoveryError::WrongCode)
        ));
    }
}

#[cfg(feature = "totp")]
mod totp_tests {
    use super::*;
    use totp_rs::{Algorithm, Secret, TOTP};

    fn code_at_offset(secret: &str, step_offset: i64) -> String {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
            Some("authery-tests".into()),
            "test".into(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = (now / 30).checked_add_signed(step_offset).unwrap();
        totp.generate(step * 30)
    }

    fn code_for(secret: &str) -> String {
        code_at_offset(secret, 0)
    }

    /// Full cycle: enroll while logged in, confirm with a real code, then the
    /// MFA policy demands TOTP on the next password login and a code
    /// completes it. The same code must not be accepted twice (replay).
    #[tokio::test]
    async fn totp_enroll_confirm_and_mfa_cycle() {
        let store = TestStore::default();

        // Signup creates an UNVERIFIED email, so TOTP will be the user's only
        // second factor - the MFA wrap must trigger on it alone.
        let logged_in = auth(&store)
            .password_signup("alice@x.com", "hunter2")
            .await
            .unwrap();
        let user_id = logged_in
            .session()
            .await
            .unwrap()
            .expect("signed up")
            .get_user_id();
        let enrollment = logged_in.totp_enroll_start("alice@x.com").await.unwrap();
        assert!(!enrollment.qr_png_base64.is_empty());
        assert!(enrollment.otpauth_url.starts_with("otpauth://totp/"));

        // Unconfirmed enrollment is not a usable factor yet.
        assert!(!logged_in.totp_enabled(&user_id).await.unwrap());

        logged_in
            .totp_enroll_confirm(&code_for(&enrollment.secret))
            .await
            .unwrap();
        assert!(logged_in.totp_enabled(&user_id).await.unwrap());

        // Fresh password login now yields a pending session (policy requires
        // MFA for passwords, and TOTP is available).
        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        assert!(pending.session().await.unwrap().is_none());

        // The confirmation consumed the current time step: replaying the
        // identical code must fail...
        let replayed = code_for(&enrollment.secret);
        match pending.mfa_totp_verify(&replayed).await {
            Err(authery::mfa::MfaTotpError::Totp(err)) => {
                assert_eq!(err.to_string(), "Wrong code")
            }
            other => panic!("expected replay rejection, got {other:?}"),
        }

        // ...but the NEXT step's code is valid even within the same
        // wall-clock window (the replay guard tracks the matched step, and
        // verification accepts one step of skew).
        let mut builder = AuthBuilder::new(store.clone());
        builder.mfa_policy = mfa_for_password();
        let pending = builder
            .build()
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        let upgraded = pending
            .mfa_totp_verify(&code_at_offset(&enrollment.secret, 1))
            .await
            .unwrap();
        let session = upgraded.session().await.unwrap().expect("logged in");
        let LoginMethod::Mfa { first, second } = session.get_method() else {
            panic!("expected Mfa session");
        };
        assert_eq!(*first, LoginMethod::Password);
        assert_eq!(*second, LoginMethod::Totp);
    }

    #[tokio::test]
    async fn totp_rejects_wrong_codes_and_disable_removes_factor() {
        let store = TestStore::default();
        let user_id = store.seed_user("alice@x.com", Some("hunter2"));

        let logged_in = auth(&store)
            .password_login("alice@x.com", "hunter2")
            .await
            .unwrap();
        let enrollment = logged_in.totp_enroll_start("alice@x.com").await.unwrap();

        // A wrong code must not confirm the enrollment.
        assert!(logged_in.totp_enroll_confirm("000000").await.is_err());
        assert!(!logged_in.totp_enabled(&user_id).await.unwrap());

        logged_in
            .totp_enroll_confirm(&code_for(&enrollment.secret))
            .await
            .unwrap();
        assert!(logged_in.totp_enabled(&user_id).await.unwrap());

        logged_in.totp_disable().await.unwrap();
        assert!(!logged_in.totp_enabled(&user_id).await.unwrap());
    }
}
