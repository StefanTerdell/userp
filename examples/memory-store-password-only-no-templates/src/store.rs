use crate::models::{MyLoginSession, MyUser};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;
use authery::{prelude::*, reexports::uuid::Uuid};

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
}

impl AutheryStore for MemoryStore {
    type User = MyUser;
    type UserId = Uuid;
    type SessionId = Uuid;
    type LoginSession = MyLoginSession;
    type Error = Infallible;

    async fn get_session(
        &self,
        session_id: &Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error> {
        let sessions = self.sessions.read().await;

        Ok(sessions.get(session_id).cloned())
    }

    async fn delete_session(&self, user_id: &Uuid, session_id: &Uuid) -> Result<(), Self::Error> {
        let mut sessions = self.sessions.write().await;

        let session = sessions.remove(session_id);

        match session {
            Some(session) if session.user_id != *user_id => panic!("User missmatch"),
            _ => Ok(()),
        }
    }

    async fn create_session(
        &self,
        user_id: &Uuid,
        method: LoginMethod,
    ) -> Result<Self::LoginSession, Self::Error> {
        let session = MyLoginSession {
            id: Uuid::new_v4(),
            user_id: *user_id,
            method,
        };

        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session.clone());

        Ok(session)
    }

    async fn get_user(&self, user_id: &Uuid) -> Result<Option<MyUser>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.get(user_id).cloned())
    }

    async fn password_get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<MyUser>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.values().find(|u| u.email == password_id).cloned())
    }

    async fn password_create_user(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<MyUser, Self::Error> {
        let mut users = self.users.write().await;

        if users.values().find(|u| u.email == password_id).is_some() {
            panic!("Address in use");
        };

        let user = MyUser {
            id: Uuid::new_v4(),
            password_hash: Some(password_hash.into()),
            email: password_id.into(),
        };

        users.insert(user.id, user.clone());

        Ok(user)
    }
}
