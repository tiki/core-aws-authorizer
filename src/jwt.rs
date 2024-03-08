/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use chrono::Duration;

use aws_lambda_events::apigw::ApiGatewayCustomAuthorizerRequestTypeRequest;
use lambda_runtime::{LambdaEvent, Error};
use jwt_compact::{alg::Es256, jwk::JsonWebKey, prelude::*, Algorithm};
use crate::{AuthContext, Payload};

type PublicKey = <Es256 as Algorithm>::VerifyingKey;

pub fn validate(
  event: &LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<AuthContext, Error> {

  let token: String = event.payload.headers
    .get("Authorization")
    .unwrap()
    .to_str()
    .unwrap()
    .to_owned()
    .replace("Bearer ", "");

  let endpoint: String = event.payload.path.as_ref().unwrap().to_string();

  let key = "";

  let jwk: JsonWebKey = serde_json::from_str(key)?;
  let public_key = PublicKey::try_from(&jwk)?;
  let token = UntrustedToken::new(&token)?;
  let token: Token<Payload> = Es256.validator(&public_key).validate(&token)?;
  return claims(&token, endpoint)
}


fn claims(token: &Token<Payload>, aud: String) -> Result<AuthContext, Error> {

  let time_options = TimeOptions::from_leeway(Duration::seconds(60));
  token.claims().validate_expiration(&time_options)?;

  if token.claims().not_before.is_some() {
      token.claims().validate_maturity(&time_options)?;
  }

  if !token
      .claims()
      .custom
      .aud
      .contains(&aud)
  {
    return Err("Invalid AUD claim".into());
  }

  if token.claims().custom.iss != "https://mytiki.com" {
    return Err("Invalid iss claim".into());
  }

  if token.claims().custom.scp.contains(&"publish".to_string()) {
    return Err("Invalid scp claim".into());
  }

  let mut splitter = token.claims().custom.sub.splitn(2, ':');
  let role = splitter.next().unwrap();
  let id = splitter.next().unwrap();
  
  Ok(AuthContext{
    role: role.to_string(),
    id: id.to_string()
  })
}