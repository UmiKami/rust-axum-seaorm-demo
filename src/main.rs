mod entities;
use entities::users;

use axum::{
    extract::{Path, State},
    routing::{get, post, delete},
    Json, Router,
};

use serde_json::{Value, json};

use dotenvy::dotenv;
use sea_orm::{ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, Iden, ModelTrait, QueryFilter, Set};
use serde::Deserialize;
use std::{env, net::SocketAddr};
use sha2::{Sha256, Digest};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};


fn to_sha256(value: &String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let hasher_res = hasher.finalize();

    return format!("{:x}", hasher_res);
}


#[derive(Clone)]
struct AppState {
    db: DatabaseConnection
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost:5432/axsea)");
    let db = Database::connect(&database_url).await?;

    let state = AppState { db };

    let app = Router::new()
        .route("/", get(|| async {Json( json!( {
            "msg": "Welcome to rust!"
        } )) } ))
        .route("/health", get(|| async { "ok" }))
        .route("/users", post(signup))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", delete(delete_user))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on http://{}", addr);
    tracing::info!("listening on http://localhost:{}", addr.port());
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener,app.into_make_service()).await?;
    Ok(())
}


#[derive(Deserialize)]
struct CreateUserPayload {
    name: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

fn bad_response(msg: String) -> Json<Value> {
    return Json(json!({ "error": msg }));
}

async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserPayload>,
) -> Result<Json<entities::users::Model>, (axum::http::StatusCode, Json<Value>)> {

    let email = payload.email.ok_or((axum::http::StatusCode::BAD_REQUEST, bad_response("Email not provided".to_string()) ))?;

    if email.is_empty() || !email.contains("@") {
        return Err((axum::http::StatusCode::BAD_REQUEST, bad_response("Invalid email address".to_string())));
    }

    let maybe_user = users::Entity::find()
        .filter(users::Column::Email.eq(&email))
        .one(&state.db)
        .await.map_err(|_| {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, bad_response("Internal server error".to_string()))
    })?;

    if let Some(user) = maybe_user {
        return Err((axum::http::StatusCode::BAD_REQUEST, bad_response("Email already exists.".to_string())))
    }

    let name = payload.name.ok_or((axum::http::StatusCode::BAD_REQUEST, bad_response("Name not provided".to_string()) ))?;
    let password = payload.password.ok_or((axum::http::StatusCode::BAD_REQUEST, bad_response("Password not provided".to_string()) ))?;

    if password.chars().count() < 8 || password.chars().count() > 64 {
        return Err((axum::http::StatusCode::BAD_REQUEST, bad_response("Password must be 8-64 characters long.".to_string())))
    }

    let hash_password = to_sha256(&password);

    let new_user = users::ActiveModel {
        name: Set(name),
        email: Set(email),
        password: Set(Option::from(hash_password)),
        ..Default::default()
    };

    match new_user.insert(&state.db).await {
        Ok(model) => Ok(Json(model)),
        Err(e) => Err((axum::http::StatusCode::BAD_REQUEST, Json(json!({"msg": e.to_string()})) )),
    }
}


async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<entities::users::Model>, axum::http::StatusCode> {
    let maybe = users::Entity::find_by_id(id).one(&state.db).await.map_err(|_| {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match maybe {
        Some(model) => Ok(Json(model)),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    
    let maybe_user_deleted = users::Entity::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if maybe_user_deleted.rows_affected > 0 {
        Ok(Json(json!({ "msg": "Record deleted successfully!" })))
    } else {
        Err(axum::http::StatusCode::NOT_FOUND)
    }

}
