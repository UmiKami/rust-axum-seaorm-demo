use axum::{
    Form, Json, Router,
    extract::{State},
    routing::{get, post, delete},
    response::IntoResponse
};

use serde_json::{Value, json};
use serde::Deserialize;

use crate::auth::{
    backend::Login,
    SeaOrmBackend
};

// DATABASE IMPORTS
use crate::entities::{
    users,
    helper::{
        db_insert,
    },
};
use sea_orm::{ ColumnTrait, EntityTrait, QueryFilter, Set};


// OTHER
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use axum::http::StatusCode;
use axum_login::login_required;
use crate::routes::helper::{bad_response, AppState, AuthSession};

pub fn router() -> Router<AppState> {
    Router::new()
        // private routes 👇
        .route("/logout", delete(logout))
        .route("/profile", get(get_user_profile))
        .route_layer(login_required!(SeaOrmBackend))
        // public routes 👇
        .route("/signup", post(signup))
        .route("/login", post(login))
}


#[derive(Deserialize)]
struct CreateUserPayload {
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
}


async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserPayload>,
) -> Result<Json<users::Model>, (StatusCode, Json<Value>)> {

    let email = payload.email.ok_or((StatusCode::BAD_REQUEST, bad_response("Email not provided".to_string()) ))?;

    if email.is_empty() || !email.contains("@") {
        return Err((StatusCode::BAD_REQUEST, bad_response("Invalid email address".to_string())));
    }

    let maybe_user = users::Entity::find()
        .filter(users::Column::Email.eq(&email))
        .one(&*state.db)
        .await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Internal server error".to_string()))
    })?;

    if let Some(_) = maybe_user {
        return Err((StatusCode::BAD_REQUEST, bad_response("Email already exists.".to_string())))
    }

    let name = payload.name.ok_or((StatusCode::BAD_REQUEST, bad_response("Name not provided".to_string()) ))?;
    let password = payload.password.ok_or((StatusCode::BAD_REQUEST, bad_response("Password not provided".to_string()) ))?;

    if password.chars().count() < 8 || password.chars().count() > 64 {
        return Err((StatusCode::BAD_REQUEST, bad_response("Password must be 8-64 characters long.".to_string())))
    }

    let salt = SaltString::generate(&mut OsRng);

    let hash_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Unable to hash password".to_string())))?
        .to_string();

    let new_user = users::ActiveModel {
        name: Set(name),
        email: Set(email),
        password: Set(Some(hash_password)),
        ..Default::default()
    };

    db_insert::<users::Entity>(state, new_user).await
}


async fn login(
    mut auth_session: AuthSession,
    Form(creds): Form<Login>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::OK, Json(json!({ "msg": "Login successful." }))).into_response()
}

async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
    let _ = auth_session
        .logout()
        .await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Logout failed".to_string())).into_response());

    (StatusCode::OK, Json(json!({ "msg": "Logout successful." }))).into_response()
}


async fn get_user_profile (
    auth_session: AuthSession
) -> Result<Json<users::Model>, (StatusCode, Json<Value>)> {
    match auth_session.user {
        Some(user) => Ok(Json(user)),
        None => Err((StatusCode::BAD_REQUEST, bad_response("User not found".to_string()))),
    }
}
