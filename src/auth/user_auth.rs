use axum_login::AuthUser;
use crate::entities::users;

impl AuthUser for users::Model {
    type Id = i32;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        match &self.password {
            Some(password_hash) => password_hash.as_bytes(),
            None => &[],
        }
    }
}