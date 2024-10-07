use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}
