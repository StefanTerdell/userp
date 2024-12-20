# Userp

## Work in progress

Warning: This crate is heavily WIP! I'm holding off on doc-comments until I've worked out the module hierarchy and basic API to my satisfaction.

## Summary

This crate provides a high-level user, authentication and session handling system for Axum, and likely Actix later on. The idea is to use it as a base for something like Next Auth but for Leptos, being easy to set up while heavy on features, with including batteris a higher approach than full customizability.

If you need something truly custom you might want to look at the awesome axum-login or oauth2 crates, but if you just want...
1. Users to be able to Log In
2. Reset their Passwords with their verified Email
3. Link their social accounts
4. Manage their multiple Sessions

... Then this might be something for you!

## Screenshots

Before you ask: design PRs are most welcome 😅

<table align="center">
<tr>
  <td align="center">
    <img alt="A screenshot of the included sign-up screen" src="https://raw.githubusercontent.com/StefanTerdell/userp/refs/heads/main/.github/sign-up.png" width="320px" />

  </td>
</tr>
<tr>
  <td align="center">
    <img alt="A screenshot of the included user account management screen" src="https://raw.githubusercontent.com/StefanTerdell/userp/refs/heads/main/.github/account-manager.png" width="500px" />
  </td>
</tr>
</table>


## Features

- Login types
  - Username / Password
  - Email magic link
  - Social logins (OAuth)
- Emails
  - Validation
  - Password reset
- Oauth
  - Easily extendable with custom providers
  - Ergonomicly implement user info fetching procedure
  - Optional split callback paths
- Batteries included
  - Askama based templates provide basic login/signup/account pages
  - Growing list of built-in social providers
  - Multiple sessions

## Todo
- [x] Granular feature-controlled templates
- [ ] Replacable templates (by typed Fns returning impl IntoResponse)
- [ ] Webauthn
- [ ] MFA
- [ ] Doc-comments
- [ ] Tests
- [ ] ???
- [ ] Publish!

