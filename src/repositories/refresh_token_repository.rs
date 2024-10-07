use diesel::prelude::*;
use diesel::sql_types::{Integer, Text, Timestamp};
use crate::Repository;
use crate::models::RefreshToken;
use crate::schema::refresh_tokens;
use diesel::result::QueryResult;
use chrono::NaiveDateTime;

pub struct RefreshTokenRepository;

type RefreshTokenTuple = (Integer, Text, Integer, Timestamp, Timestamp);

impl<Conn> Repository<Conn> for RefreshTokenRepository
where
    Conn: diesel::Connection + diesel::connection::LoadConnection,
    Conn::Backend: diesel::backend::Backend
        + diesel::sql_types::HasSqlType<Integer>
        + diesel::sql_types::HasSqlType<Text>
        + diesel::sql_types::HasSqlType<Timestamp>
        + diesel::sql_types::HasSqlType<diesel::sql_types::BigInt>
        + 'static,
    String: ToSql<Text, Conn::Backend>,
    i32: ToSql<Integer, Conn::Backend>,
    RefreshToken: Queryable<RefreshTokenTuple, Conn::Backend> + QueryableByName<Conn::Backend> + QueryId + AsChangeset,
{
    type Model = RefreshToken;
    type NewModel = RefreshToken;
    type SqlType = RefreshTokenTuple;

    fn create(&self, conn: &mut Conn, new_token: &Self::NewModel) -> QueryResult<Self::Model> {
        diesel::insert_into(refresh_tokens::table)
            .values(new_token)
            .get_result(conn)
    }

    fn find_by_id(&self, conn: &mut Conn, token_id: i32) -> QueryResult<Option<Self::Model>> {
        refresh_tokens::table.find(token_id).first(conn).optional()
    }

    fn update(&self, conn: &mut Conn, token_id: i32, updated_token: &Self::NewModel) -> QueryResult<Self::Model> {
        diesel::update(refresh_tokens::table.find(token_id))
            .set(updated_token)
            .get_result(conn)
    }

    fn delete(&self, conn: &mut Conn, token_id: i32) -> QueryResult<usize> {
        diesel::delete(refresh_tokens::table.find(token_id)).execute(conn)
    }
}

impl RefreshTokenRepository {
    pub fn find_by_token<Conn>(conn: &mut Conn, token: &str) -> QueryResult<Option<RefreshToken>>
    where
        Conn: diesel::Connection,
        Conn::Backend: diesel::backend::Backend
            + diesel::sql_types::HasSqlType<Integer>
            + diesel::sql_types::HasSqlType<Text>
            + diesel::sql_types::HasSqlType<Timestamp>
            + diesel::sql_types::HasSqlType<diesel::sql_types::BigInt>
            + 'static,
        RefreshToken: Queryable<RefreshTokenTuple, Conn::Backend> + QueryableByName<Conn::Backend> + QueryId + AsChangeset,
        String: ToSql<Text, Conn::Backend>,
    {
        use crate::schema::refresh_tokens::dsl::*;
        refresh_tokens
            .filter(token.eq(token))
            .first(conn)
            .optional()
    }

    pub fn delete_by_user_id<Conn>(conn: &mut Conn, user_id: i32) -> QueryResult<usize>
    where
        Conn: diesel::Connection,
        Conn::Backend: diesel::backend::Backend
            + diesel::sql_types::HasSqlType<Integer>
            + diesel::sql_types::HasSqlType<diesel::sql_types::BigInt>
            + 'static,
        i32: ToSql<Integer, Conn::Backend>,
    {
        use crate::schema::refresh_tokens::dsl::*;
        diesel::delete(refresh_tokens.filter(user_id.eq(user_id)))
            .execute(conn)
    }
}
