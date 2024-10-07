use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::pg::{PgConnection, Pg};
use diesel::result::QueryResult;
use diesel::query_builder::AsChangeset;
use diesel::associations::HasTable;
use log::{info, error};

pub mod schema;
pub mod models;
pub mod controllers;
pub mod repositories;
pub mod dto;
pub mod services;
pub mod errors;
pub mod middleware;

#[cfg(test)]
pub type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

#[cfg(not(test))]
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub trait Repository {
    type Model: Queryable<Self::SqlType, Pg> + QueryableByName<Pg> + AsChangeset + HasTable;
    type NewModel: Insertable<<Self::Model as HasTable>::Table> + AsChangeset;
    type SqlType;

    fn create(&self, conn: &mut PgConnection, new_model: &Self::NewModel) -> QueryResult<Self::Model>;
    fn find_by_id(&self, conn: &mut PgConnection, id: i32) -> QueryResult<Option<Self::Model>>;
    fn update(&self, conn: &mut PgConnection, id: i32, updated_model: &Self::NewModel) -> QueryResult<Self::Model>;
    fn delete(&self, conn: &mut PgConnection, id: i32) -> QueryResult<usize>;
}

#[macro_export]
macro_rules! register_controller {
    ($app:expr, $path:expr, $controller:path) => {
        $app.service(
            web::scope($path)
                .configure($controller::configure)
        )
    };
}

#[cfg(not(test))]
pub fn establish_connection_pool() -> DbPool {
    use std::time::Duration;
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    match r2d2::Pool::builder()
        .max_size(15)
        .min_idle(Some(5))
        .connection_timeout(Duration::from_secs(10))
        .idle_timeout(Some(Duration::from_secs(300)))
        .build(manager) {
        Ok(pool) => {
            info!("Successfully established database connection pool");
            pool
        },
        Err(e) => {
            error!("Failed to create database connection pool: {:?}", e);
            panic!("Failed to create pool: {:?}", e);
        }
    }
}

#[cfg(test)]
pub fn establish_connection_pool() -> DbPool {
    let database_url = ":memory:".to_string();
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

#[cfg(not(test))]
pub fn run_migrations(conn: &mut PgConnection) {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    conn.run_pending_migrations(MIGRATIONS).expect("Failed to run migrations");
}

#[cfg(test)]
pub fn run_migrations(conn: &mut SqliteConnection) {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    conn.run_pending_migrations(MIGRATIONS).expect("Failed to run migrations");
}
