use std::sync::Arc;
use axum::Json;
use sea_orm::DatabaseConnection;
use serde_json::{json, Value};
use crate::auth::SeaOrmBackend;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseConnection>
}

pub type AuthSession = axum_login::AuthSession<SeaOrmBackend>;


pub fn bad_response(msg: String) -> Json<Value> {
    Json(json!({ "error": msg }))
}