mod entities;
mod auth;
mod routes;

// AXUM RELATED IMPORTS
use axum::{
    http::{HeaderValue, Method},
    Json,
    routing::{get},
    Router
};

use axum_csrf_simple::{csrf_protect, get_csrf_token, set_csrf_secure_cookie_enable, set_csrf_token_sign_key};
use axum_login::{tower_sessions::SessionManagerLayer, AuthManagerLayerBuilder};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_sessions::{
    cookie::time::Duration,
    session_store::ExpiredDeletion,
    Expiry,
};
use tower_sessions_sqlx_store::{sqlx::PgPool, PostgresStore};

use crate::auth::SeaOrmBackend;

// DATABASE IMPORTS
use sea_orm::Database;

// SYSTEM IMPORTS
use dotenvy::dotenv;
use std::sync::Arc;
use std::{env, net::SocketAddr};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// OTHER

use routes::helper::AppState;

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
        .route("/", get(|| async {Json( json!( {
            "msg": "Welcome to rust!"
        } )) } ))
        .nest("/users", routes::users::router())
        .nest("/todos", routes::todos::router())
        .route("/health", get(|| async { "ok" }))
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