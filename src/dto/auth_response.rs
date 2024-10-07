use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
}
