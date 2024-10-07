use actix_web::{test, web, App};
use rust_web_server::{
    establish_connection_pool, run_migrations,
    controllers::auth,
    dto::{RegisterUser, LoginUser},
    middleware::jwt_auth,
    DbPool,
};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use serde_json::json;
use uuid::Uuid;
use log::debug;
use actix_web::http::StatusCode;
use actix_web::dev::Service;
use dotenv::dotenv;

fn setup_test_db() -> DbPool {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

fn teardown(pool: &DbPool) {
    let conn = &mut pool.get().expect("Failed to get db connection from pool");
    diesel::sql_query("TRUNCATE TABLE users, refresh_tokens CASCADE").execute(conn).unwrap();
}

#[actix_web::test]
async fn test_login_and_protected_endpoint() {
    env_logger::init();
    dotenv().ok();
    let pool = setup_test_db();

    debug!("Setting up test application");
    let app = test::init_service(
        App::new()
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
    ).await;
    debug!("Test application set up complete");

    let unique_username = format!("testuser_{}", Uuid::new_v4());
    let unique_email = format!("{}@example.com", Uuid::new_v4());

    // Register a user
    debug!("Registering a new user");
    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": unique_username,
            "email": unique_email,
            "password": "testpassword123"
        }))
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert_eq!(register_resp.status(), 201, "Registration failed");

    // Login
    debug!("Logging in with the new user");
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(json!({
            "username": unique_username,
            "password": "testpassword123"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status(), 200, "Login failed");

    let login_body: serde_json::Value = test::read_body_json(login_resp).await;
    let token = login_body["token"].as_str().expect("Token not found in response");
    debug!("Received token: {}", token);

    // Test unauthenticated access to protected endpoint
    debug!("Sending unauthenticated request to protected endpoint");
    let unauth_req = test::TestRequest::get()
        .uri("/api/protected/test")
        .to_request();
    let unauth_resp = app.call(unauth_req).await;

    assert!(unauth_resp.is_err(), "Unauthenticated request should be rejected");
    let error = unauth_resp.unwrap_err();
    assert_eq!(error.to_string(), "Missing Authorization header", "Unexpected error message");

    debug!("Unauthenticated request correctly rejected");

    // Test authenticated access to protected endpoint
    debug!("Sending authenticated request to protected endpoint");
    let auth_req = test::TestRequest::get()
        .uri("/api/protected/test")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let auth_resp = test::call_service(&app, auth_req).await;

    assert_eq!(auth_resp.status(), StatusCode::OK, "Authenticated request should be accepted");
    let auth_body = test::read_body(auth_resp).await;
    let auth_body_str = String::from_utf8(auth_body.to_vec()).expect("Failed to convert body to string");
    assert_eq!(auth_body_str, "This is a protected endpoint", "Unexpected response from protected endpoint");

    debug!("Authenticated request correctly accepted");

    teardown(&pool);
}
