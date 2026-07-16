# Passwords

`PasswordConfig::new()` gives argon2 hashing on a blocking thread pool.
Swap the hasher with `.with_hasher(...)` (the trait is `PasswordHasher`).

Login is enumeration-resistant: unknown users and wrong passwords return the
same error, and comparable hash work is burned on the miss paths so timing
doesn't reveal account existence.

With `email` also enabled, password reset works over emailed links:
`PasswordReset::VerifiedEmailOnly` (default) or `AnyUserEmail`, configured
via `.with_allow_reset(...)`. Reset links create single-use, purpose-bound
sessions that cannot access anything but the reset flow, and are logged out
after the password changes.
