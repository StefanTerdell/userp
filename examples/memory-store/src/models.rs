use authery::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        uuid::Uuid,
    },
};

#[derive(Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub emails: Vec<MyUserEmail>,
}

impl User for MyUser {
    type Id = Uuid;

    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug, Clone)]
pub struct MyUserEmail {
    pub user_id: Uuid,
    pub email: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

impl UserEmail for MyUserEmail {
    type UserId = Uuid;

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_address(&self) -> &str {
        self.email.as_str()
    }

    fn get_verified(&self) -> bool {
        self.verified
    }

    fn get_allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

#[derive(Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
    pub expires: DateTime<Utc>,
}

impl LoginSession for MyLoginSession {
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

#[derive(Clone, Debug)]
pub struct MyEmailChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

impl EmailChallenge for MyEmailChallenge {
    fn get_address(&self) -> &str {
        &self.address
    }

    fn get_code(&self) -> &str {
        &self.code
    }

    fn get_next(&self) -> &Option<String> {
        &self.next
    }

    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

impl OAuthToken for MyOAuthToken {
    type Id = Uuid;
    type UserId = Uuid;

    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_provider_name(&self) -> &str {
        self.provider_name.as_str()
    }

    fn get_refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }
}

#[derive(Debug, Clone)]
pub struct MyOrganization {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub slug: String,
    pub name: String,
    pub login_rules: OrgLoginRules,
    pub role_inheritance: Vec<(String, String)>,
}

impl Organization for MyOrganization {
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
        self.login_rules.clone()
    }

    fn get_role_inheritance(&self) -> Vec<(String, String)> {
        self.role_inheritance.clone()
    }
}

#[derive(Debug, Clone)]
pub struct MyOrgMember {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub roles: Vec<String>,
}

impl OrgMember for MyOrgMember {
    type UserId = Uuid;
    type OrgId = Uuid;

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_org_id(&self) -> Uuid {
        self.org_id
    }

    fn get_roles(&self) -> Vec<String> {
        self.roles.clone()
    }
}

#[derive(Debug, Clone)]
pub struct MyOrgOidcProvider {
    pub org_id: Uuid,
    pub config: authery::models::org::NewOrgOidcProvider,
}

impl authery::models::org::OrgOidcProvider for MyOrgOidcProvider {
    type OrgId = Uuid;

    fn get_org_id(&self) -> Uuid {
        self.org_id
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    fn get_display_name(&self) -> &str {
        &self.config.display_name
    }

    fn get_client_id(&self) -> &str {
        &self.config.client_id
    }

    fn get_client_secret(&self) -> &str {
        &self.config.client_secret
    }

    fn get_issuer(&self) -> &str {
        &self.config.issuer
    }

    fn get_auth_url(&self) -> &str {
        &self.config.auth_url
    }

    fn get_token_url(&self) -> &str {
        &self.config.token_url
    }

    fn get_scopes(&self) -> Vec<String> {
        self.config.scopes.clone()
    }

    fn get_allow_login(&self) -> bool {
        self.config.allow_login
    }

    fn get_default_roles(&self) -> Vec<String> {
        self.config.default_roles.clone()
    }

    fn get_claim_role_mapping(&self) -> Vec<(String, String, String)> {
        self.config.claim_role_mapping.clone()
    }
}

#[derive(Debug, Clone)]
pub struct MyOrgInvite {
    pub org_id: Uuid,
    pub code: String,
    pub roles: Vec<String>,
    pub expires: DateTime<Utc>,
}

impl OrgInvite for MyOrgInvite {
    type OrgId = Uuid;

    fn get_org_id(&self) -> Uuid {
        self.org_id
    }

    fn get_code(&self) -> &str {
        &self.code
    }

    fn get_roles(&self) -> Vec<String> {
        self.roles.clone()
    }

    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}
