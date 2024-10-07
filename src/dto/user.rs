use serde::{Serialize, Deserialize};
use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Insertable, Debug, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    #[diesel(column_name = id)]
    pub id: i32,
    #[diesel(column_name = username)]
    pub username: String,
    #[diesel(column_name = email)]
    pub email: String,
    #[diesel(column_name = password_hash)]
    pub password_hash: String,
    #[diesel(column_name = created_at)]
    pub created_at: NaiveDateTime,
}
