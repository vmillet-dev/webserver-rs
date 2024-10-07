use actix_web::{web, App, HttpServer, http};
use actix_cors::Cors;
use rust_web_server::{
    controllers::auth,
    establish_connection_pool, run_migrations,
    middleware::jwt_auth,
};
use log::{info, error};
use dotenv::dotenv;
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();
    info!("Starting application");

    let pool = establish_connection_pool();
    info!("Database connection pool established");

    let conn = &mut pool.get().expect("Failed to get DB connection from pool");
    info!("Got connection from pool");

    run_migrations(conn);
    info!("Migrations completed");

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/auth")
                            .configure(auth::configure_public_routes)
                    )
                    .service(
                        web::scope("/protected")
                            .wrap(jwt_auth())
                            .configure(auth::configure_protected_routes)
                    )
            )
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_test() {
        assert!(true);
    }
}
