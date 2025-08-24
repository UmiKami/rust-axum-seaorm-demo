use crate::auth::SeaOrmBackend;

pub async fn get_user_id(auth_session: axum_login::AuthSession<SeaOrmBackend>) -> i32 {
    let user_id =  match auth_session.user {
        Some(user) => user,
        _ => return -1
    };
    
    user_id.id
}