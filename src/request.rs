use serde::Deserialize;

#[derive(Deserialize)]
pub struct Request {
  pub body: String,
}
