use diesel::prelude::*;
use chrono::NaiveDateTime;
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable, AsChangeset, QueryableByName, Debug)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: NaiveDateTime,
    pub refresh_token: Option<String>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub refresh_token: Option<&'a str>,
    pub created_at: NaiveDateTime,
}

#[derive(Queryable, Selectable, Identifiable, AsChangeset, QueryableByName)]
#[diesel(table_name = crate::schema::refresh_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct RefreshToken {
    pub id: i32,
    pub user_id: i32,
    pub token: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::refresh_tokens)]
pub struct NewRefreshToken<'a> {
    pub user_id: i32,
    pub token: &'a str,
    pub expires_at: NaiveDateTime,
}

impl RefreshToken {
    pub fn generate(user_id: i32, expiration: chrono::Duration) -> NewRefreshToken<'static> {
        let token = Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().naive_utc() + expiration;
        NewRefreshToken {
            user_id,
            token: Box::leak(token.into_boxed_str()),
            expires_at,
        }
    }
}
