use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};

use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

mod iam_policy;
mod jwt_service;

#[derive(Serialize, Deserialize)]
pub struct AuthContext {
    provider: String,
    address: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct JWTK {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    uses: String,
    e: String,
    n: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredKeys {
    keys: HashMap<String, JWTK>,
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    uid: String,
    sub: String,      // Optional. Subject (whom token refers to)
    scp: Vec<String>, // Optional. Scopes (permissions)>
}

async fn function_handler(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthContext>, Error> {
    let token: String = event.payload.headers
      .get("Authorization")
      .unwrap()
      .to_str()
      .unwrap()
      .to_owned();

    let token_data: Result<jsonwebtoken::TokenData<Claims>, anyhow::Error> =
        jwt_service::validate_token(&token);

    let resp = iam_policy::prepare_response(token_data);

    return Ok(resp.unwrap());
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    run(service_fn(|event| function_handler(event))).await
}
