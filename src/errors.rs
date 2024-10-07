use actix_web::{HttpResponse, ResponseError};
use derive_more::Display;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    InternalServerError(String),
    BadRequest(String),
    Unauthorized(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ApiError::InternalServerError(msg) => write!(f, "Internal Server Error: {}", msg),
            ApiError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::InternalServerError(_) => HttpResponse::InternalServerError().json("Internal Server Error"),
            ApiError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
            ApiError::Unauthorized(ref message) => HttpResponse::Unauthorized().json(message),
        }
    }
}
