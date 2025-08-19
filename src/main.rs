mod entities;
mod auth;

use entities::users;

use axum::{extract::{Path, State}, routing::{get, post, delete}, Form, Json, Router};

use serde_json::{Value, json};

use dotenvy::dotenv;
use sea_orm::{ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use std::{env, net::SocketAddr};
use std::sync::Arc;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use axum::http::Method;
use axum::response::IntoResponse;
use axum_login::{login_required, permission_required, tower_sessions::{MemoryStore, SessionManagerLayer}, AuthManagerLayerBuilder};
use tower_http::cors::{AllowCredentials, Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::auth::backend::Login;
use crate::auth::SeaOrmBackend;

#[derive(Clone)]
struct AppState {
    db: Arc<DatabaseConnection>
}



#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_origin("http://localhost:5173".parse::<HeaderValue>()?)
        .allow_headers([hyper::header::CONTENT_TYPE])
        .allow_credentials(true);

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost:5432/axsea)");
    let db = Database::connect(&database_url).await?;
    let db = Arc::new(db);

    let state = AppState { db: db.clone() }; // clone Arc
    let backend = SeaOrmBackend { conn: db.clone() }; // same Arc

    // Connect sqlx Postgres pool for sessions
    let session_db_url = env::var("SESSION_DATABASE_URL")
        .expect("SESSION_DATABASE_URL must be set (postgres://user:pass@localhost:5432/sessions)");
    let pool = PgPool::connect(&session_db_url).await?;

    let session_store = PostgresStore::new(pool);
    session_store.migrate().await?; // creates the sessions table

    // background cleanup task for expired sessions
    tokio::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
    );

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // only disable in dev; enable in prod
        .with_expiry(Expiry::OnInactivity(Duration::seconds(30)));

    let auth_layer = AuthManagerLayerBuilder::new(backend.clone(), session_layer).build();

    let app = Router::new()
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", delete(delete_user))
        .route_layer(login_required!(SeaOrmBackend))
        .route("/", get(|| async {Json( json!( {
            "msg": "Welcome to rust!"
        } )) } ))
        .route("/health", get(|| async { "ok" }))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/login", get(login))
        .layer(auth_layer)
        .layer(cors)
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
        .one(&*state.db)
        .await.map_err(|_| {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, bad_response("Internal server error".to_string()))
    })?;

    if let Some(_) = maybe_user {
        return Err((axum::http::StatusCode::BAD_REQUEST, bad_response("Email already exists.".to_string())))
    }

    let name = payload.name.ok_or((axum::http::StatusCode::BAD_REQUEST, bad_response("Name not provided".to_string()) ))?;
    let password = payload.password.ok_or((axum::http::StatusCode::BAD_REQUEST, bad_response("Password not provided".to_string()) ))?;

    if password.chars().count() < 8 || password.chars().count() > 64 {
        return Err((axum::http::StatusCode::BAD_REQUEST, bad_response("Password must be 8-64 characters long.".to_string())))
    }

    let salt = SaltString::generate(&mut OsRng);

    let hash_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, bad_response("Unable to hash password".to_string())))?
        .to_string();

    let new_user = users::ActiveModel {
        name: Set(name),
        email: Set(email),
        password: Set(Some(hash_password)),
        ..Default::default()
    };

    match new_user.insert(&*state.db).await {
        Ok(model) => Ok(Json(model)),
        Err(e) => Err((axum::http::StatusCode::BAD_REQUEST, Json(json!({"msg": e.to_string()})) )),
    }
}

type AuthSession = axum_login::AuthSession<SeaOrmBackend>;



async fn login(
    mut auth_session: AuthSession,
    Form(creds): Form<Login>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    axum::http::StatusCode::OK.into_response()
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<entities::users::Model>, axum::http::StatusCode> {
    let maybe = users::Entity::find_by_id(id).one(&*state.db).await.map_err(|_| {
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
        .exec(&*state.db)
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
