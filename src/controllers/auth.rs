use actix_web::{web, HttpResponse};
use crate::DbPool;
use crate::dto::{RegisterUser, LoginUser};
use crate::services::auth_service;
use crate::errors::ApiError;

pub async fn register(
    pool: web::Data<DbPool>,
    user_info: web::Json<RegisterUser>,
) -> Result<HttpResponse, ApiError> {
    auth_service::register(pool, user_info).await
}

pub async fn login(
    pool: web::Data<DbPool>,
    user_info: web::Json<LoginUser>,
) -> Result<HttpResponse, ApiError> {
    auth_service::login(pool, user_info).await
}

pub async fn refresh(
    pool: web::Data<DbPool>,
    refresh_token: web::Json<String>,
) -> Result<HttpResponse, ApiError> {
    auth_service::refresh_token(pool, refresh_token).await
}

pub async fn protected_endpoint(
    _: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok().body("This is a protected endpoint"))
}

pub fn configure_public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/refresh", web::post().to(refresh))
    );
}

pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/test", web::get().to(protected_endpoint))
    );
}
