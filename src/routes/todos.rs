use axum::{
    extract::State, routing::{get, put},
    Json,
    Router
};

use serde::Deserialize;
use serde_json::{json, Value};

// DATABASE IMPORTS
use crate::entities::{helper::db_insert, todos};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, Order, QueryFilter, QueryOrder, Set};

use crate::auth;
use crate::auth::SeaOrmBackend;
use crate::entities::prelude::Todos;
use crate::routes::helper::{bad_response, AppState, AuthSession};
use axum::extract::Path;
use axum::http::StatusCode;
use axum_login::login_required;


pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_todos).post(create_todo))
        .route("/{id}", put(update_todo).delete(delete_todo))
        .route_layer(login_required!(SeaOrmBackend))
}


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
        })?;

    Ok(Json(maybe_todos))
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

    let todo: Option<todos::Model> = Todos::find()
        .filter(todos::Column::UserId.eq(user_id).and(todos::Column::Id.eq(id)))
        .one(&*state.db)
        .await
        .map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, bad_response("Something went wrong with DB.".to_string()))
        })?;

    let mut todo: todos::ActiveModel = match todo {
        None => {
            return Err((StatusCode::NOT_FOUND, bad_response("Either task does not exist or you do not own it.".to_string())))
        }
        Some(active_model) => active_model.into()
    };

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
