use diesel::prelude::*;
use crate::Repository;
use crate::models::{User, NewUser};
use crate::schema::users;
use diesel::result::QueryResult;
use diesel::pg::PgConnection;
use diesel::sql_types::{Integer, Text, Timestamp, Nullable};

pub struct UserRepository;

impl Repository for UserRepository {
    type Model = User;
    type NewModel = NewUser<'static>;
    type SqlType = (Integer, Text, Text, Text, Timestamp, Nullable<Text>);

    fn create(&self, conn: &mut PgConnection, new_user: &Self::NewModel) -> QueryResult<Self::Model> {
        diesel::insert_into(users::table)
            .values(new_user)
            .get_result(conn)
    }

    fn find_by_id(&self, conn: &mut PgConnection, user_id: i32) -> QueryResult<Option<Self::Model>> {
        users::table.find(user_id).first(conn).optional()
    }

    fn update(&self, conn: &mut PgConnection, user_id: i32, updated_user: &Self::NewModel) -> QueryResult<Self::Model> {
        diesel::update(users::table.find(user_id))
            .set(updated_user)
            .get_result(conn)
    }

    fn delete(&self, conn: &mut PgConnection, user_id: i32) -> QueryResult<usize> {
        diesel::delete(users::table.find(user_id)).execute(conn)
    }
}

impl UserRepository {
    pub fn find_by_username(conn: &mut PgConnection, _username: &str) -> QueryResult<Option<User>> {
        use crate::schema::users::dsl::*;
        users
            .filter(username.eq(_username))
            .first(conn)
            .optional()
    }
}
