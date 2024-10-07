use crate::dto::{AuthResponse, LoginUser, RegisterUser};
use crate::errors::ApiError;
use crate::models::{NewUser, User, RefreshToken, NewRefreshToken};
use crate::repositories::user_repository::UserRepository;
use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use jsonwebtoken::{encode, EncodingKey, Header};
use bcrypt::{hash, verify};
use serde::{Deserialize, Serialize};
use std::env;
use actix_web::{cookie::Cookie, HttpResponse, web};
use diesel::prelude::*;
use uuid::Uuid;

#[cfg(test)]
use diesel::sqlite::SqliteConnection;
#[cfg(not(test))]
use diesel::pg::PgConnection;

#[cfg(test)]
type DbConnection = SqliteConnection;
#[cfg(not(test))]
type DbConnection = PgConnection;

type DbPool = web::Data<r2d2::Pool<ConnectionManager<DbConnection>>>;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn register(pool: DbPool, user: web::Json<RegisterUser>) -> Result<HttpResponse, ApiError> {
    log::debug!("Starting registration process for user: {}", user.username);
    let conn = &mut pool.get().map_err(|e| {
        log::error!("Failed to get DB connection: {:?}", e);
        ApiError::InternalServerError(e.to_string())
    })?;

    // Input validation
    if user.username.is_empty() || user.email.is_empty() || user.password.is_empty() {
        log::warn!("Registration failed: Empty fields");
        return Err(ApiError::BadRequest("All fields are required".to_string()));
    }
    if user.password.len() < 8 {
        log::warn!("Registration failed: Password too short");
        return Err(ApiError::BadRequest("Password must be at least 8 characters long".to_string()));
    }
    // Add more validation as needed (e.g., email format, username restrictions)

    let hashed_password = hash(&user.password, 12).map_err(|e| {
        log::error!("Failed to hash password: {:?}", e);
        ApiError::InternalServerError(e.to_string())
    })?;

    let new_user = NewUser {
        username: &user.username,
        email: &user.email,
        password_hash: &hashed_password,
        refresh_token: None,
        created_at: Utc::now().naive_utc(),
    };

    log::debug!("Attempting to insert new user into database");
    #[cfg(test)]
    let created_user = {
        diesel::insert_into(crate::schema::users::table)
            .values(&new_user)
            .execute(conn)
            .map_err(|e| {
                log::error!("Failed to insert user (test): {:?}", e);
                ApiError::InternalServerError(e.to_string())
            })?;
        crate::schema::users::table
            .order(crate::schema::users::id.desc())
            .first::<User>(conn)
            .map_err(|e| {
                log::error!("Failed to fetch created user (test): {:?}", e);
                ApiError::InternalServerError(e.to_string())
            })?
    };

    #[cfg(not(test))]
    let created_user = diesel::insert_into(crate::schema::users::table)
        .values(&new_user)
        .get_result::<User>(conn)
        .map_err(|e| {
            log::error!("Failed to insert user: {:?}", e);
            ApiError::InternalServerError(e.to_string())
        })?;

    log::debug!("User created successfully: {:?}", created_user);

    // Generate JWT token
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let claims = Claims {
        sub: created_user.id.to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| {
        log::error!("Failed to generate JWT token: {:?}", e);
        ApiError::InternalServerError(e.to_string())
    })?;

    // Generate a refresh token
    let new_refresh_token = NewRefreshToken {
        user_id: created_user.id,
        token: &Uuid::new_v4().to_string(),
        expires_at: (Utc::now() + Duration::days(7)).naive_utc(),
    };
    let refresh_token_str = new_refresh_token.token.to_string();

    // Store the refresh token in the database
    log::debug!("Storing refresh token in database");
    diesel::insert_into(crate::schema::refresh_tokens::table)
        .values(&new_refresh_token)
        .execute(conn)
        .map_err(|e| {
            log::error!("Failed to store refresh token: {:?}", e);
            ApiError::InternalServerError(e.to_string())
        })?;

    let cookie = Cookie::build("refresh_token", refresh_token_str.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();

    log::info!("Registration successful for user: {}", user.username);

    Ok(HttpResponse::Created()
        .cookie(cookie)
        .json(AuthResponse {
            token,
            refresh_token: refresh_token_str,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        }))
}

pub async fn login(pool: DbPool, login_user: web::Json<LoginUser>) -> Result<HttpResponse, ApiError> {
    use crate::schema::users::dsl::*;
    log::debug!("Login attempt for user: {}", login_user.username);
    let conn = &mut pool.get().map_err(|e| {
        log::error!("Failed to get DB connection: {:?}", e);
        ApiError::InternalServerError("Couldn't get db connection from pool".to_string())
    })?;

    log::debug!("Attempting to fetch user: {}", login_user.username);
    let user_result = users
        .filter(username.eq(&login_user.username))
        .first::<User>(conn)
        .optional()
        .map_err(|e| {
            log::error!("Database error while fetching user: {:?}", e);
            ApiError::InternalServerError("Failed to fetch user".to_string())
        })?;

    let user = match user_result {
        Some(u) => {
            log::debug!("User found: {:?}", u);
            u
        },
        None => {
            log::warn!("User not found: {}", login_user.username);
            return Err(ApiError::Unauthorized("Invalid username or password".to_string()));
        }
    };

    log::debug!("Stored password hash: {}", user.password_hash);
    log::debug!("Provided password: {}", login_user.password);

    let verification_result = verify(&login_user.password, &user.password_hash);
    log::debug!("Password verification result: {:?}", verification_result);

    if !verification_result.map_err(|e| {
        log::error!("Failed to verify password: {:?}", e);
        ApiError::InternalServerError("Failed to verify password".to_string())
    })? {
        log::warn!("Invalid password for user: {}", login_user.username);
        return Err(ApiError::Unauthorized("Invalid username or password".to_string()));
    }

    log::debug!("User authenticated successfully: {}", login_user.username);

    let claims = Claims {
        sub: user.id.to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
    };

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_ref()))
        .map_err(|e| {
            log::error!("Failed to generate token: {:?}", e);
            ApiError::InternalServerError("Failed to generate token".to_string())
        })?;

    // Generate a refresh token
    let new_refresh_token = NewRefreshToken {
        user_id: user.id,
        token: &Uuid::new_v4().to_string(),
        expires_at: (Utc::now() + Duration::days(7)).naive_utc(),
    };
    let refresh_token_str = new_refresh_token.token.to_string();

    // Store the refresh token in the database
    log::debug!("Storing refresh token in database");
    diesel::insert_into(crate::schema::refresh_tokens::table)
        .values(&new_refresh_token)
        .execute(conn)
        .map_err(|e| {
            log::error!("Failed to store refresh token: {:?}", e);
            ApiError::InternalServerError("Failed to store refresh token".to_string())
        })?;

    let cookie = Cookie::build("refresh_token", refresh_token_str.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();

    log::info!("Login successful for user: {}", login_user.username);

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(AuthResponse {
            token,
            refresh_token: refresh_token_str,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        }))
}

pub async fn refresh_token(pool: DbPool, refresh_token: web::Json<String>) -> Result<HttpResponse, ApiError> {
    let conn = &mut pool.get().map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    let refresh_token_data = crate::schema::refresh_tokens::table
        .filter(crate::schema::refresh_tokens::token.eq(refresh_token.as_str()))
        .first::<RefreshToken>(conn)
        .optional()
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("Invalid refresh token".to_string()))?;

    if Utc::now().naive_utc() > refresh_token_data.expires_at {
        return Err(ApiError::Unauthorized("Refresh token has expired".to_string()));
    }

    let user = crate::schema::users::table
        .find(refresh_token_data.user_id)
        .first::<User>(conn)
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    // Generate new JWT token
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let claims = Claims {
        sub: user.id.to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    // Generate new refresh token
    let new_refresh_token = NewRefreshToken {
        user_id: user.id,
        token: &Uuid::new_v4().to_string(),
        expires_at: (Utc::now() + Duration::days(7)).naive_utc(),
    };
    let new_refresh_token_str = new_refresh_token.token.to_string();

    // Update refresh token in the database
    diesel::delete(crate::schema::refresh_tokens::table.filter(crate::schema::refresh_tokens::token.eq(refresh_token.as_str())))
        .execute(conn)
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?;
    diesel::insert_into(crate::schema::refresh_tokens::table)
        .values(&new_refresh_token)
        .execute(conn)
        .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

    let cookie = Cookie::build("refresh_token", new_refresh_token_str.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(AuthResponse {
            token,
            refresh_token: new_refresh_token_str,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        }))
}
