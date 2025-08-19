use std::sync::Arc;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use axum_login::{AuthSession, AuthUser, AuthnBackend};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde::Deserialize;
use crate::entities::users;


#[derive(Clone)]
pub struct SeaOrmBackend {
    pub conn: Arc<DatabaseConnection>,
}

#[derive(Deserialize, Clone)]
pub struct Login {
    email: String,
    password: String,
}

impl AuthnBackend for SeaOrmBackend {
    type User = users::Model;
    type Credentials = Login;
    type Error = sea_orm::DbErr;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let Login {email, password} = creds;

        if let Some(user) = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(&*self.conn)
            .await?
        {
            // If password_hash is None, immediately reject login
            if let Some(ref stored_hash) = user.password {
                if let Ok(parsed_hash) = PasswordHash::new(stored_hash) {
                    if Argon2::default()
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok()
                    {
                        return Ok(Some(user));
                    }
                }
            }
        }

        Ok(None)
    }
    async fn get_user(&self, user_id: &<Self::User as AuthUser>::Id) -> Result<Option<Self::User>, Self::Error> {
        let user = users::Entity::find_by_id(*user_id)
            .one(&*self.conn)
            .await?;
        Ok(user)
    }
}