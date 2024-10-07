// @generated automatically by Diesel CLI.

diesel::table! {
    refresh_tokens (id) {
        id -> Int4,
        user_id -> Int4,
        #[max_length = 255]
        token -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    temp_users (id) {
        id -> Int4,
        #[max_length = 255]
        username -> Varchar,
        #[max_length = 255]
        password -> Varchar,
    }
}

diesel::table! {
    todos (id) {
        id -> Int4,
        title -> Varchar,
        completed -> Bool,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        email -> Varchar,
        password_hash -> Varchar,
        created_at -> Timestamp,
        refresh_token -> Nullable<Varchar>,
    }
}

diesel::joinable!(refresh_tokens -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    refresh_tokens,
    temp_users,
    todos,
    users,
);
