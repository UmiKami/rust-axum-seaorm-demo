use std::env;
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
    o_auth_accounts
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use reqwest::Client;

// OTHER
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use axum_login::login_required;
use crate::routes::helper::{bad_response, AppState, AuthSession};
use oauth_axum::providers::github::GithubProvider;
use oauth_axum::{ OAuthClient};
use sea_orm::sea_query::token;
use tower_sessions::Session;
use crate::entities::users::Model;

#[derive(Clone, serde::Deserialize)]
pub struct QueryAxumCallback {
    pub code: String,
    pub state: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        // private routes 👇
        .route("/logout", delete(logout))
        .route("/profile", get(get_user_profile))
        .route_layer(login_required!(SeaOrmBackend))
        // public routes 👇
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/login/github", get(oauth_github_create_url))
        .route("/github/callback", get(oauth_github_callback))
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

// region OAUTH GitHub

pub async fn oauth_github_create_url( session: Session) -> String {
    let github_client_id: String = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    let github_client_secret: String = env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set");
    let redirect_url: String = "http://localhost:3000/users/github/callback".to_string();

    let state_oauth = GithubProvider::new(
        github_client_id,
        github_client_secret,
        redirect_url
    )
        .generate_url(
            Vec::from(["users.read".to_string()]),
            |state_e| async move {
                //SAVE THE DATA IN THE DB OR MEMORY
                //state should be your ID
                session
                    .insert("oauth_state", &state_e.state)
                    .await
                    .unwrap();
                session
                    .insert("oauth_verifier", &state_e.verifier)
                    .await
                    .unwrap();
            },
        )
        .await
        .ok()
        .unwrap()
        .state
        .unwrap();

    state_oauth.url_generated.unwrap()
}

#[derive(Deserialize, Debug)]
struct GithubUser {
    login: String,
    id: u64,
    avatar_url: Option<String>,
    email: Option<String>,
    name: Option<String>,
}
async fn fetch_github_user(token: &str) -> anyhow::Result<GithubUser> {
    let client = Client::new();
    let user: GithubUser = client
        .get("https://api.github.com/user")
        .bearer_auth(token)
        .header("User-Agent", "AxumSeaOrmDemo") // GitHub requires this
        .send()
        .await?
        .json()
        .await?;
    Ok(user)
}
pub async fn oauth_github_callback(
    State(state): State<AppState>,
    session: Session,
    Query(queries): Query<QueryAxumCallback>,
    mut auth_session: AuthSession, // needed to log in user if linked
) -> Response {
    // --- 1. Validate OAuth state from session ---
    let expected_state: Option<String> = session.get("oauth_state").await.unwrap();
    let verifier: Option<String> = session.get("oauth_verifier").await.unwrap();

    if expected_state.is_none() || verifier.is_none() {
        return (StatusCode::BAD_REQUEST, bad_response("OAuth session missing".into())).into_response();
    }

    if queries.state != expected_state.clone().unwrap() {
        return (StatusCode::BAD_REQUEST, bad_response("Invalid state".into())).into_response();
    }

    // --- 2. Exchange code for token ---
    let github_client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    let github_client_secret = env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set");
    let redirect_url: String = "http://localhost:3000/users/github/callback".to_string();

    let token = match GithubProvider::new(
        github_client_id,
        github_client_secret,
        redirect_url,
    )
        .generate_token(queries.code, verifier.unwrap())
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate token: {:?}",  match e {
                oauth_axum::error::OauthError::TokenRequestFailed => {
                    "Token request failed"
                }
                oauth_axum::error::OauthError::AuthUrlCreationFailed => {
                    "Auth url creation failed"
                }
            });
            (StatusCode::BAD_REQUEST, bad_response("Token exchange failed".into())).into_response()
        }) {
        Ok(token) => {token}
        Err(e) => {
            return e
        }
    };

    // cleanup session values
    session.remove::<String>("oauth_state").await.unwrap();
    session.remove::<String>("oauth_verifier").await.unwrap();

    // --- 3. Fetch GitHub user profile ---
    let github_user = match fetch_github_user(&token).await
        .map_err(|_| (StatusCode::BAD_REQUEST, bad_response("Failed to fetch GitHub user profile".into())).into_response())
    {
        Ok(user) => {user}
        Err(e) => {
            return e
        }
    };

    // --- 4. Check if oauth account exists ---
    let existing_account = o_auth_accounts::Entity::find()
        .filter(o_auth_accounts::Column::Provider.eq("github"))
        .filter(o_auth_accounts::Column::ProviderAccountId.eq(github_user.id.to_string()))
        .one(&*state.db)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, bad_response("DB lookup failed".into())));

    if let Ok(Some(account)) = existing_account {
        // already linked → fetch related user
        let user = match account.find_related(users::Entity)
            .one(&*state.db)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, bad_response("User lookup failed".into())).into_response())
        {
            Ok(model) => {model.unwrap()}
            Err(e) => {
                 return e;
            }
        };


        // log them in
        auth_session.login(&user).await.unwrap();

        let redirect = Redirect::temporary("http://localhost:5173/");
        return redirect.into_response();
    };

    // --- 5. Not linked yet ---
    if let Some(current_user) = &auth_session.user {
        // logged-in user → link GitHub account to them
        let new_oauth = o_auth_accounts::ActiveModel {
            provider: Set("github".to_string()),
            provider_account_id: Set(github_user.id.to_string()),
            access_token: Set(Some(token.clone())),
            refresh_token: Set(None), // GitHub usually doesn’t give refresh_token
            user_id: Set(Some(current_user.id)),
            ..Default::default()
        };
        new_oauth.insert(&*state.db).await.unwrap();

        let redirect = Redirect::temporary("http://localhost:5173/");
        return redirect.into_response();
    }

    // not linked & not logged in → ask user to log in first
    (StatusCode::UNAUTHORIZED, bad_response(
        "No linked account. Please log in first to connect GitHub.".into()
    )).into_response()
}

// regionend