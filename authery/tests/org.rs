//! Integration tests for the organizations feature, run with:
//!   cargo test -p authery --test org --features organizations,password
#![cfg(all(feature = "organizations", feature = "password"))]

use authery::models::org::{OrgLoginRules, OrgMember as _, OrgPrivilege, Organization as _};
use authery::models::{AutheryCookies, LoginMethod, LoginSession, User};
use authery::org::{OrgConfig, OrgError};
use authery::prelude::PasswordConfig;
use authery::ratelimit::NoRateLimit;
use authery::reexports::chrono::{DateTime, Duration, Utc};
use authery::reexports::uuid::Uuid;
use authery::routes::Routes;
use authery::core::CoreAuthery;
use authery::store::AutheryStore;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct TestUser {
    id: Uuid,
}

impl User for TestUser {
    type Id = Uuid;
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_password_hash(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone)]
struct TestSession {
    id: Uuid,
    user_id: Uuid,
    method: LoginMethod,
    expires: DateTime<Utc>,
}

impl LoginSession for TestSession {
    type Id = Uuid;
    type UserId = Uuid;
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }
    fn get_method(&self) -> LoginMethod {
        self.method.clone()
    }
    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Debug, Clone)]
struct TestOrg {
    id: Uuid,
    parent: Option<Uuid>,
    slug: String,
    name: String,
    rules: OrgLoginRules,
    inheritance: Vec<(String, String)>,
    privilege_inheritance: Vec<(OrgPrivilege, OrgPrivilege)>,
}

impl authery::models::org::Organization for TestOrg {
    type Id = Uuid;
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_parent_id(&self) -> Option<Uuid> {
        self.parent
    }
    fn get_slug(&self) -> &str {
        &self.slug
    }
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_login_rules(&self) -> OrgLoginRules {
        self.rules.clone()
    }
    fn get_role_inheritance(&self) -> Vec<(String, String)> {
        self.inheritance.clone()
    }
    fn get_privilege_inheritance(&self) -> Vec<(OrgPrivilege, OrgPrivilege)> {
        self.privilege_inheritance.clone()
    }
}

#[derive(Debug, Clone)]
struct TestMember {
    user_id: Uuid,
    org_id: Uuid,
    privilege: Option<OrgPrivilege>,
    roles: Vec<String>,
}

impl authery::models::org::OrgMember for TestMember {
    type UserId = Uuid;
    type OrgId = Uuid;
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }
    fn get_org_id(&self) -> Uuid {
        self.org_id
    }
    fn get_privilege(&self) -> Option<OrgPrivilege> {
        self.privilege
    }
    fn get_roles(&self) -> Vec<String> {
        self.roles.clone()
    }
}

#[derive(Debug, Clone)]
struct TestInvite {
    org_id: Uuid,
    code: String,
    privilege: Option<OrgPrivilege>,
    roles: Vec<String>,
    expires: DateTime<Utc>,
}

impl authery::models::org::OrgInvite for TestInvite {
    type OrgId = Uuid;
    fn get_org_id(&self) -> Uuid {
        self.org_id
    }
    fn get_code(&self) -> &str {
        &self.code
    }
    fn get_privilege(&self) -> Option<OrgPrivilege> {
        self.privilege
    }
    fn get_roles(&self) -> Vec<String> {
        self.roles.clone()
    }
    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Debug, Clone, Default)]
struct TestStore {
    users: Arc<Mutex<HashMap<Uuid, TestUser>>>,
    sessions: Arc<Mutex<HashMap<Uuid, TestSession>>>,
    orgs: Arc<Mutex<HashMap<Uuid, TestOrg>>>,
    members: Arc<Mutex<Vec<TestMember>>>,
    invites: Arc<Mutex<HashMap<String, TestInvite>>>,
}

impl AutheryStore for TestStore {
    type Error = Infallible;
    type UserId = Uuid;
    type SessionId = Uuid;
    type OrgId = Uuid;
    type User = TestUser;
    type LoginSession = TestSession;
    type Organization = TestOrg;
    type OrgMember = TestMember;
    type OrgInvite = TestInvite;

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<TestUser>, Infallible> {
        Ok(self.users.lock().unwrap().get(user_id).cloned())
    }

    async fn create_session(
        &self,
        user_id: &Uuid,
        method: LoginMethod,
        expires: DateTime<Utc>,
    ) -> Result<TestSession, Infallible> {
        let session = TestSession {
            id: Uuid::new_v4(),
            user_id: *user_id,
            method,
            expires,
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id, session.clone());
        Ok(session)
    }

    async fn get_session(&self, session_id: &Uuid) -> Result<Option<TestSession>, Infallible> {
        Ok(self.sessions.lock().unwrap().get(session_id).cloned())
    }

    async fn delete_session(&self, _user_id: &Uuid, session_id: &Uuid) -> Result<(), Infallible> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &Uuid) -> Result<Vec<TestSession>, Infallible> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.user_id == *user_id)
            .cloned()
            .collect())
    }

    async fn delete_user(&self, id: &Uuid) -> Result<(), Infallible> {
        self.users.lock().unwrap().remove(id);
        Ok(())
    }

    async fn password_get_user_by_password_id(
        &self,
        _password_id: &str,
    ) -> Result<Option<TestUser>, Infallible> {
        Ok(None)
    }

    async fn password_create_user(
        &self,
        _password_id: &str,
        _password_hash: &str,
    ) -> Result<TestUser, Infallible> {
        let user = TestUser { id: Uuid::new_v4() };
        self.users.lock().unwrap().insert(user.id, user.clone());
        Ok(user)
    }

    async fn clear_user_password_hash(
        &self,
        _user_id: &Uuid,
        _session_id: &Uuid,
    ) -> Result<(), Infallible> {
        Ok(())
    }

    async fn set_user_password_hash(
        &self,
        _user_id: &Uuid,
        _password_hash: String,
        _session_id: &Uuid,
    ) -> Result<(), Infallible> {
        Ok(())
    }

    async fn org_create(
        &self,
        name: &str,
        slug: &str,
        parent: Option<&Uuid>,
    ) -> Result<TestOrg, Infallible> {
        let org = TestOrg {
            id: Uuid::new_v4(),
            parent: parent.copied(),
            slug: slug.to_string(),
            name: name.to_string(),
            rules: OrgLoginRules::default(),
            inheritance: Vec::new(),
            privilege_inheritance: Vec::new(),
        };
        self.orgs.lock().unwrap().insert(org.id, org.clone());
        Ok(org)
    }

    async fn org_get(&self, org_id: &Uuid) -> Result<Option<TestOrg>, Infallible> {
        Ok(self.orgs.lock().unwrap().get(org_id).cloned())
    }

    async fn org_get_by_slug(&self, slug: &str) -> Result<Option<TestOrg>, Infallible> {
        Ok(self
            .orgs
            .lock()
            .unwrap()
            .values()
            .find(|o| o.slug == slug)
            .cloned())
    }

    async fn org_get_children(&self, org_id: &Uuid) -> Result<Vec<TestOrg>, Infallible> {
        Ok(self
            .orgs
            .lock()
            .unwrap()
            .values()
            .filter(|o| o.parent == Some(*org_id))
            .cloned()
            .collect())
    }

    async fn org_update(
        &self,
        org_id: &Uuid,
        name: &str,
        login_rules: OrgLoginRules,
        role_inheritance: Vec<(String, String)>,
        privilege_inheritance: Vec<(OrgPrivilege, OrgPrivilege)>,
    ) -> Result<(), Infallible> {
        if let Some(org) = self.orgs.lock().unwrap().get_mut(org_id) {
            org.name = name.to_string();
            org.rules = login_rules;
            org.inheritance = role_inheritance;
            org.privilege_inheritance = privilege_inheritance;
        }
        Ok(())
    }

    async fn org_delete(&self, org_id: &Uuid) -> Result<(), Infallible> {
        self.orgs.lock().unwrap().remove(org_id);
        self.members.lock().unwrap().retain(|m| m.org_id != *org_id);
        Ok(())
    }

    async fn org_upsert_member(
        &self,
        org_id: &Uuid,
        user_id: &Uuid,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
    ) -> Result<TestMember, Infallible> {
        let mut members = self.members.lock().unwrap();
        members.retain(|m| !(m.org_id == *org_id && m.user_id == *user_id));
        let member = TestMember {
            user_id: *user_id,
            org_id: *org_id,
            privilege,
            roles,
        };
        members.push(member.clone());
        Ok(member)
    }

    async fn org_remove_member(&self, org_id: &Uuid, user_id: &Uuid) -> Result<(), Infallible> {
        self.members
            .lock()
            .unwrap()
            .retain(|m| !(m.org_id == *org_id && m.user_id == *user_id));
        Ok(())
    }

    async fn org_get_member(
        &self,
        org_id: &Uuid,
        user_id: &Uuid,
    ) -> Result<Option<TestMember>, Infallible> {
        Ok(self
            .members
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.org_id == *org_id && m.user_id == *user_id)
            .cloned())
    }

    async fn org_get_members(&self, org_id: &Uuid) -> Result<Vec<TestMember>, Infallible> {
        Ok(self
            .members
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.org_id == *org_id)
            .cloned()
            .collect())
    }

    async fn org_invite_create(
        &self,
        org_id: &Uuid,
        code: &str,
        privilege: Option<OrgPrivilege>,
        roles: Vec<String>,
        expires: DateTime<Utc>,
    ) -> Result<TestInvite, Infallible> {
        let invite = TestInvite {
            org_id: *org_id,
            code: code.to_string(),
            privilege,
            roles,
            expires,
        };
        self.invites
            .lock()
            .unwrap()
            .insert(code.to_string(), invite.clone());
        Ok(invite)
    }

    async fn org_invite_consume(&self, code: &str) -> Result<Option<TestInvite>, Infallible> {
        Ok(self.invites.lock().unwrap().remove(code))
    }

    async fn org_get_user_memberships(&self, user_id: &Uuid) -> Result<Vec<TestMember>, Infallible> {
        Ok(self
            .members
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.user_id == *user_id)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Clone, Default)]
struct TestCookies(HashMap<String, String>);

impl AutheryCookies for TestCookies {
    fn add(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_string(), value.to_string());
    }
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn remove(&mut self, key: &str) {
        self.0.remove(key);
    }
    fn list_encoded(&self) -> Vec<String> {
        self.0.iter().map(|(k, v)| format!("{k}={v}")).collect()
    }
}

fn auth(store: TestStore, private_orgs: bool) -> CoreAuthery<TestStore, TestCookies> {
    CoreAuthery {
        routes: Routes::default().with_prefix(""),
        allow_signup: authery::models::Allow::OnSelf,
        allow_login: authery::models::Allow::OnSelf,
        session_lifetime: Duration::days(1),
        max_concurrent_sessions: None,
        rate_limiter: Arc::new(NoRateLimit),
        cookies: TestCookies::default(),
        store,
        pass: PasswordConfig::new(),
        org_config: OrgConfig {
            create_private_org_on_signup: private_orgs,
        },
    }
}

fn new_user(store: &TestStore) -> Uuid {
    let user = TestUser { id: Uuid::new_v4() };
    store.users.lock().unwrap().insert(user.id, user.clone());
    user.id
}

/// Log the given user in through the core flow (which runs the org hooks).
async fn login(
    auth: CoreAuthery<TestStore, TestCookies>,
    user_id: Uuid,
    method: LoginMethod,
) -> CoreAuthery<TestStore, TestCookies> {
    auth.log_in(method, &user_id).await.unwrap()
}

#[tokio::test]
async fn private_org_created_on_first_login() {
    let store = TestStore::default();
    let user_id = new_user(&store);

    let auth = auth(store.clone(), true);
    let auth = login(auth, user_id, LoginMethod::Password).await;

    let memberships = store.org_get_user_memberships(&user_id).await.unwrap();
    assert_eq!(memberships.len(), 1, "private org membership created");
    assert_eq!(memberships[0].get_privilege(), Some(OrgPrivilege::Owner));
    assert!(memberships[0].get_roles().is_empty(), "no app roles granted");

    // A second login must not create another org.
    let auth = login(auth, user_id, LoginMethod::Password).await;
    let memberships = store.org_get_user_memberships(&user_id).await.unwrap();
    assert_eq!(memberships.len(), 1, "no duplicate private org");
    drop(auth);
}

#[tokio::test]
async fn no_private_org_when_disabled() {
    let store = TestStore::default();
    let user_id = new_user(&store);

    let auth = auth(store.clone(), false);
    let _auth = login(auth, user_id, LoginMethod::Password).await;

    assert!(store
        .org_get_user_memberships(&user_id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn org_management_requires_owner() {
    let store = TestStore::default();
    let owner_id = new_user(&store);
    let outsider_id = new_user(&store);

    let owner_auth = login(auth(store.clone(), false), owner_id, LoginMethod::Password).await;
    let org = owner_auth.org_create("ACME", "acme").await.unwrap();

    // The creator can manage.
    owner_auth
        .org_upsert_member(&org.get_id(), &outsider_id, None, vec!["member".into()])
        .await
        .unwrap();

    // An unprivileged member cannot.
    let member_auth = login(
        auth(store.clone(), false),
        outsider_id,
        LoginMethod::Password,
    )
    .await;
    let err = member_auth
        .org_upsert_member(
            &org.get_id(),
            &outsider_id,
            Some(OrgPrivilege::Owner),
            Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, OrgError::MissingPrivilege(_)));
}

#[tokio::test]
async fn role_inheritance_flows_into_sub_orgs() {
    let store = TestStore::default();
    let owner_id = new_user(&store);

    let owner_auth = login(auth(store.clone(), false), owner_id, LoginMethod::Password).await;
    let parent = owner_auth.org_create("ACME", "acme").await.unwrap();
    let child = owner_auth
        .org_create_sub(&parent.get_id(), "ACME R&D", "acme-rnd")
        .await
        .unwrap();

    // Give the owner an app role in the parent, map it onto "auditor" in
    // the child, map the parent's Owner privilege onto Manager, and drop the
    // creator's direct child membership so only inheritance remains.
    owner_auth
        .org_upsert_member(
            &parent.get_id(),
            &owner_id,
            Some(OrgPrivilege::Owner),
            vec!["hq".into()],
        )
        .await
        .unwrap();
    owner_auth
        .org_update(
            &child.get_id(),
            "ACME R&D",
            OrgLoginRules::default(),
            vec![("hq".into(), "auditor".into())],
            vec![(OrgPrivilege::Owner, OrgPrivilege::Manager)],
        )
        .await
        .unwrap();
    store
        .org_remove_member(&child.get_id(), &owner_id)
        .await
        .unwrap();

    let membership = owner_auth
        .org_effective_membership(&child.get_id(), &owner_id)
        .await
        .unwrap();
    assert_eq!(membership.roles, vec!["auditor".to_string()]);
    assert_eq!(
        membership.privilege,
        Some(OrgPrivilege::Manager),
        "parent Owner maps to Manager here, not Owner"
    );
}

#[tokio::test]
async fn invite_joins_org_and_suppresses_private_org() {
    use authery::models::org::OrgInvite;

    let store = TestStore::default();
    let owner_id = new_user(&store);
    let invitee_id = new_user(&store);

    let owner_auth = login(auth(store.clone(), true), owner_id, LoginMethod::Password).await;
    let org = owner_auth.org_create("ACME", "acme").await.unwrap();

    let invite = owner_auth
        .org_invite_create(&org.get_id(), None, vec!["dev".into()], Duration::hours(1))
        .await
        .unwrap();

    // The invitee logs in holding the invite cookie (private orgs enabled).
    let mut invitee_auth = auth(store.clone(), true);
    invitee_auth.org_set_invite_cookie(invite.get_code());
    let _invitee_auth = login(invitee_auth, invitee_id, LoginMethod::Password).await;

    let memberships = store.org_get_user_memberships(&invitee_id).await.unwrap();
    assert_eq!(memberships.len(), 1, "joined via invite, no private org");
    assert_eq!(memberships[0].get_org_id(), org.get_id());
    assert_eq!(memberships[0].get_roles(), vec!["dev".to_string()]);

    // The invite is single-use.
    assert!(store
        .org_invite_consume(invite.get_code())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn org_session_enforces_login_rules_and_membership() {
    let store = TestStore::default();
    let owner_id = new_user(&store);
    let outsider_id = new_user(&store);

    let owner_auth = login(auth(store.clone(), false), owner_id, LoginMethod::Password).await;
    let org = owner_auth.org_create("ACME", "acme").await.unwrap();

    // Member with a password session and default rules: allowed.
    assert!(owner_auth.org_session(&org.get_id()).await.unwrap().is_some());

    // Non-member: no org session.
    let outsider_auth = login(
        auth(store.clone(), false),
        outsider_id,
        LoginMethod::Password,
    )
    .await;
    assert!(outsider_auth
        .org_session(&org.get_id())
        .await
        .unwrap()
        .is_none());

    // Disallow passwords: the member's password session no longer counts.
    owner_auth
        .org_update(
            &org.get_id(),
            "ACME",
            OrgLoginRules {
                allow_password: false,
                ..OrgLoginRules::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(owner_auth.org_session(&org.get_id()).await.unwrap().is_none());

    // Require MFA: a plain password session is rejected too.
    owner_auth
        .org_update(
            &org.get_id(),
            "ACME",
            OrgLoginRules {
                require_mfa: true,
                ..OrgLoginRules::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(owner_auth.org_session(&org.get_id()).await.unwrap().is_none());
}

#[tokio::test]
async fn manager_tier_cannot_escalate() {
    let store = TestStore::default();
    let owner_id = new_user(&store);
    let manager_id = new_user(&store);
    let member_id = new_user(&store);

    let owner_auth = login(auth(store.clone(), false), owner_id, LoginMethod::Password).await;
    let org = owner_auth.org_create("ACME", "acme").await.unwrap();
    owner_auth
        .org_upsert_member(
            &org.get_id(),
            &manager_id,
            Some(OrgPrivilege::Manager),
            Vec::new(),
        )
        .await
        .unwrap();

    let manager_auth = login(
        auth(store.clone(), false),
        manager_id,
        LoginMethod::Password,
    )
    .await;

    // Managers handle day-to-day membership...
    manager_auth
        .org_upsert_member(&org.get_id(), &member_id, None, vec!["dev".into()])
        .await
        .unwrap();
    manager_auth
        .org_invite_create(&org.get_id(), None, vec!["dev".into()], Duration::hours(1))
        .await
        .unwrap();

    // ...but cannot grant privileges (not even to themselves),
    assert!(matches!(
        manager_auth
            .org_upsert_member(
                &org.get_id(),
                &manager_id,
                Some(OrgPrivilege::Owner),
                Vec::new()
            )
            .await
            .unwrap_err(),
        OrgError::MissingPrivilege(OrgPrivilege::Owner)
    ));

    // ...cannot touch or remove privileged members,
    assert!(matches!(
        manager_auth
            .org_upsert_member(&org.get_id(), &owner_id, None, vec!["demoted".into()])
            .await
            .unwrap_err(),
        OrgError::MissingPrivilege(OrgPrivilege::Owner)
    ));
    assert!(matches!(
        manager_auth
            .org_remove_member(&org.get_id(), &owner_id)
            .await
            .unwrap_err(),
        OrgError::MissingPrivilege(OrgPrivilege::Owner)
    ));

    // ...cannot create privilege-carrying invites,
    assert!(matches!(
        manager_auth
            .org_invite_create(
                &org.get_id(),
                Some(OrgPrivilege::Manager),
                Vec::new(),
                Duration::hours(1)
            )
            .await
            .unwrap_err(),
        OrgError::MissingPrivilege(OrgPrivilege::Owner)
    ));

    // ...and cannot reach owner-only surfaces.
    assert!(matches!(
        manager_auth.org_delete(&org.get_id()).await.unwrap_err(),
        OrgError::MissingPrivilege(OrgPrivilege::Owner)
    ));
}
