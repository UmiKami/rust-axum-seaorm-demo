mod entities;
mod auth;

// AXUM RELATED IMPORTS
use axum::{
    Form, Json, Router,
    extract::{Path, State},
    routing::{get, post, delete, put},
    http::{HeaderValue, Method},
    response::IntoResponse
};

use axum_login::{login_required, tower_sessions::{ SessionManagerLayer}, AuthManagerLayerBuilder};
use axum_csrf_simple::{csrf_protect, get_csrf_token, set_csrf_secure_cookie_enable, set_csrf_token_sign_key};
use tower_http::cors::{CorsLayer};
use tower_sessions::{
    Expiry,
    session_store::ExpiredDeletion,
    cookie::time::Duration,
};
use tower_sessions_sqlx_store::{sqlx::PgPool, PostgresStore};
use serde_json::{Value, json};
use serde::Deserialize;

use crate::auth::{
    backend::Login,
    SeaOrmBackend
};

// DATABASE IMPORTS
use entities::{
    users,
    todos,
    helper::{
        db_insert,
    },
};
use sea_orm::{ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, ModelTrait, Order, QueryFilter, QueryOrder, Set};

// SYSTEM IMPORTS
use dotenvy::dotenv;
use std::{env, net::SocketAddr};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// OTHER
use argon2::{
    password_hash::{
        rand_core::OsRng,
         PasswordHasher, SaltString
    },
    Argon2
};
use axum::http::StatusCode;
use crate::entities::prelude::Todos;
// region local helper functions

fn bad_response(msg: String) -> Json<Value> {
    Json(json!({ "error": msg }))
}

// endregion

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
        .allow_headers([hyper::header::CONTENT_TYPE, "X-CSRF-TOKEN".parse()?])
        .allow_credentials(true);

    let csrf_key = env::var("CSRF_SESSION_KEY").map_err(|_| anyhow::anyhow!("CSRF_SESSION_KEY not set"))?;
    set_csrf_token_sign_key(csrf_key.as_str()).await;
    set_csrf_secure_cookie_enable(true).await;

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost:5432/axum_seaorm_demo)");
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
        .with_expiry(Expiry::OnInactivity(Duration::seconds(3600)));

    let auth_layer = AuthManagerLayerBuilder::new(backend.clone(), session_layer).build();

    let app = Router::new()
        .route("/users/{id}", get(get_user))
        .route("/profile", get(get_user_profile))
        .route("/users/{id}", delete(delete_user))
        .route("/todos", get(get_todos))
        .route("/todos", post(create_todo))
        .route("/todos/{id}", put(update_todo))
        .route("/todos/{id}", delete(delete_todo))
        .route("/logout", delete(logout))
        .route_layer(login_required!(SeaOrmBackend))
        .route("/", get(|| async {Json( json!( {
            "msg": "Welcome to rust!"
        } )) } ))
        .route("/health", get(|| async { "ok" }))
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/get-token", get(get_csrf_token))
        .route_layer(axum::middleware::from_fn(csrf_protect))
        .layer(auth_layer)
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on http://{}", addr);
    tracing::info!("listening on http://localhost:{}", addr.port());

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(anyhow::Error::new)?;
    axum::serve(listener,app.into_make_service()).await?;
    Ok(())
}

// region User Endpoints

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

type AuthSession = axum_login::AuthSession<SeaOrmBackend>;

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

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<users::Model>, StatusCode> {
    let maybe = users::Entity::find_by_id(id).one(&*state.db).await.map_err(|_| {
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match maybe {
        Some(model) => Ok(Json(model)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_user_profile (
    auth_session: AuthSession
) -> Result<Json<users::Model>, (StatusCode, Json<Value>)> {
    match auth_session.user {
        Some(user) => Ok(Json(user)),
        None => Err((StatusCode::BAD_REQUEST, bad_response("User not found".to_string()))),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<Value>, StatusCode> {
    
    let maybe_user_deleted = users::Entity::delete_by_id(id)
        .exec(&*state.db)
        .await
        .map_err(|e| {
            tracing::error!("DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if maybe_user_deleted.rows_affected > 0 {
        Ok(Json(json!({ "msg": "Record deleted successfully!" })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }

}

// endregion

// region todos

#[derive(Deserialize)]
struct CreateTodoPayload {
    is_done: Option<bool>,
    text: String,
}

async fn create_todo(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Json(payload): Json<CreateTodoPayload>,
) -> Result<Json<todos::Model>, (StatusCode, Json<Value>)> {
    let text = payload.text;
    let is_done = Ok(payload.is_done.unwrap_or(false));

    let new_todo = todos::ActiveModel {
        text: Set(text),
        is_done: Set(is_done?),
        user_id: Set(auth::helper::get_user_id(auth_session).await),
        ..Default::default()
    };

    db_insert::<todos::Entity>(state, new_todo).await
}

async fn get_todos(
    State(state): State<AppState>,
    auth_session: AuthSession,
) -> Result<Json<Vec<todos::Model>>, (StatusCode, Json<Value>)> {
    let user_id = auth::helper::get_user_id(auth_session).await;

    if user_id < 0 {
        return Err((StatusCode::BAD_REQUEST, bad_response("Unable to identify user.".to_string())));
    }

    let maybe_todos = todos::Entity::find()
        .filter(todos::Column::UserId.eq(user_id))
        .order_by(todos::Column::Id, Order::Desc)
        .all(&*state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Something went wrong with DB.".to_string()))
        });


    match maybe_todos {
        Ok(todos) => { Ok(Json(todos))}
        Err(_) => Err((StatusCode::NOT_FOUND, bad_response("No todos found for user.".to_string())))
    }
}

#[derive(Deserialize)]
struct UpdateTodoPayload {
    is_done: Option<bool>,
    text: Option<String>,
}

async fn update_todo(
    State(state): State<AppState>,
    auth_session: AuthSession,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateTodoPayload>,
) -> Result<Json<todos::Model>, (StatusCode, Json<Value>)> {

    let text = payload.text.unwrap_or("".to_string());
    let is_done = payload.is_done;
    let user_id = auth::helper::get_user_id(auth_session).await;

    if user_id < 0 {
        return Err((StatusCode::BAD_REQUEST, bad_response("Unable to identify user.".to_string())));
    }

    let todo: Option<todos::Model> = Todos::find_by_id(id)
        .one(&*state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Something went wrong with DB.".to_string()))
        })?;

    let mut todo: todos::ActiveModel = todo.unwrap().into();

    if todo.user_id.clone().unwrap() != user_id {
        return Err((StatusCode::FORBIDDEN, bad_response("You do not own this todo.".to_string())))
    }


    if !text.is_empty() {
        todo.text = Set(text);
    };

    match is_done {
        Some(true) => {
            todo.is_done = Set(true);
        },
        Some(false) => {
            todo.is_done = Set(false);
        },

        None => {}
    }

    let updated_todo: todos::Model = match todo.update(&*state.db).await {
        Ok(model) => model,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                bad_response("Update failed.".to_string()),
            ));
        }
    };

    Ok(Json(updated_todo))
}

async fn delete_todo(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    auth_session: AuthSession,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user_id = auth::helper::get_user_id(auth_session).await;

    if user_id < 0 {
        return Err((StatusCode::BAD_REQUEST, bad_response("Unable to identify user.".to_string())));
    }

    
    let todo: todos::Model = match Todos::find()
        .filter(todos::Column::UserId.eq(user_id).and(todos::Column::Id.eq(id)))
        .one(&*state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Something went wrong while attempting to find task.".to_string()))
        })? {
            Some(model) => model,
            _ => {
                return Err((StatusCode::NOT_FOUND, bad_response("Task not found.".to_string())))
            }
    };

    let res = todo.delete(&*state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Something went wrong while attempting to delete task.".to_string()))
        })?;

    if res.rows_affected == 1 {
        return Ok(Json(json!({ "msg": "Deleted task" })))
    }

    Err((StatusCode::BAD_REQUEST, bad_response("Something went very wrong..".to_string())))

}

// endregion