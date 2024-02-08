use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Response {
  pub req_id: String,
  pub body: String,
}

impl std::error::Error for Response {}

impl std::fmt::Display for Response {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      let err_as_json = serde_json::json!(self).to_string();
      write!(f, "{err_as_json}")
  }
}
