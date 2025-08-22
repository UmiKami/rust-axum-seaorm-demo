use axum::{
    http::{StatusCode}
};
use axum::Json;
use sea_orm::{EntityTrait, ActiveModelTrait, IntoActiveModel};
use serde_json::{json, Value};
use crate::AppState;


pub async fn db_insert<E>(state: AppState, model: E::ActiveModel) -> Result<Json<E::Model>, (StatusCode, Json<Value>)>
where
    E: EntityTrait,
    E::ActiveModel: ActiveModelTrait<Entity = E> + Send,
    E::Model: IntoActiveModel<E::ActiveModel>,
{
    match model.insert(&*state.db).await {
        Ok(model) => Ok(Json(model)),
        Err(e) => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"msg": e.to_string()})))),
    }
}