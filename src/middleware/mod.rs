use actix_web::dev::{ServiceRequest, ServiceResponse, Transform, Service};
use actix_web::{Error, HttpMessage};
use futures::future::{Ready, ok};
use futures::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::dto::Claims;
use std::env;
use log::debug;

pub struct JwtAuth;

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtAuthMiddleware { service })
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        debug!("JwtAuthMiddleware: Processing request");
        let auth_header = req.headers().get("Authorization");
        debug!("JwtAuthMiddleware: Authorization header: {:?}", auth_header);
        match auth_header {
            Some(auth_value) => {
                let auth_str = auth_value.to_str().unwrap_or("");
                debug!("JwtAuthMiddleware: Authorization string: {}", auth_str);
                if !auth_str.starts_with("Bearer ") {
                    debug!("JwtAuthMiddleware: Invalid Authorization header format");
                    return Box::pin(async move {
                        Err(actix_web::error::ErrorUnauthorized("Invalid Authorization header format"))
                    });
                }

                let token = &auth_str[7..]; // Remove "Bearer " prefix
                debug!("JwtAuthMiddleware: Extracted token: {}", token);
                let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(jwt_secret.as_ref()),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        debug!("JwtAuthMiddleware: Token successfully decoded");
                        req.extensions_mut().insert(token_data.claims);
                        let fut = self.service.call(req);
                        Box::pin(async move {
                            fut.await
                        })
                    }
                    Err(e) => {
                        debug!("JwtAuthMiddleware: Token decoding failed: {:?}", e);
                        Box::pin(async move {
                            Err(actix_web::error::ErrorUnauthorized("Invalid token"))
                        })
                    },
                }
            }
            None => {
                debug!("JwtAuthMiddleware: Missing Authorization header");
                Box::pin(async move {
                    Err(actix_web::error::ErrorUnauthorized("Missing Authorization header"))
                })
            },
        }
    }
}

pub fn jwt_auth() -> JwtAuth {
    JwtAuth
}
