use actix_web::dev::{ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, HttpResponse};
use actix_web::http::StatusCode;
use jsonwebtoken::{decode, DecodingKey, Validation};
use crate::dto::Claims;
use std::env;
use futures::future::{ok, Ready};
use actix_web::dev::Service;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use log::debug;

pub struct JwtMiddleware;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService { service })
    }
}

pub struct JwtMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
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
        let auth_header = req.headers().get("Authorization");

        debug!("JwtAuthMiddleware: Processing request");
        debug!("JwtAuthMiddleware: Authorization header: {:?}", auth_header);

        Box::pin(async move {
            match auth_header {
                Some(auth_value) => {
                    let auth_str = auth_value.to_str().map_err(|_| {
                        debug!("JwtAuthMiddleware: Invalid Authorization header");
                        Error::from(actix_web::error::ErrorUnauthorized("Invalid Authorization header"))
                    })?;

                    if !auth_str.starts_with("Bearer ") {
                        debug!("JwtAuthMiddleware: Invalid token format");
                        return Err(Error::from(actix_web::error::ErrorUnauthorized("Invalid token format")));
                    }

                    let token = &auth_str[7..]; // Remove "Bearer " prefix
                    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

                    match decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(jwt_secret.as_ref()),
                        &Validation::default(),
                    ) {
                        Ok(token_data) => {
                            debug!("JwtAuthMiddleware: Token validated successfully");
                            req.extensions_mut().insert(token_data.claims);
                            let fut = self.service.call(req);
                            fut.await
                        }
                        Err(e) => {
                            debug!("JwtAuthMiddleware: Token validation failed: {:?}", e);
                            Err(Error::from(actix_web::error::ErrorUnauthorized("Invalid token")))
                        }
                    }
                }
                None => {
                    debug!("JwtAuthMiddleware: Missing Authorization header");
                    Err(Error::from(actix_web::error::ErrorUnauthorized("Missing Authorization header")))
                }
            }
        })
    }
}

pub fn jwt_auth() -> JwtMiddleware {
    JwtMiddleware
}
