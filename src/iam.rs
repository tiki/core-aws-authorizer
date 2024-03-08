/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */
use crate::AuthContext;

use aws_lambda_events::apigw::{
  ApiGatewayCustomAuthorizerRequestTypeRequest,
  ApiGatewayCustomAuthorizerResponse,  
  ApiGatewayCustomAuthorizerPolicy, 
  IamPolicyStatement,
};

use lambda_runtime::{LambdaEvent, Error};

pub fn policy(
  event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>, 
  validation: Result<String, Error>) -> 
  anyhow::Result<ApiGatewayCustomAuthorizerResponse<AuthContext>, Error> {

let path = event.payload.method_arn.unwrap();

let id: String = match validation {
  Ok(id) => id,
  Err(_) => "".to_string()
};

let statement: Vec<IamPolicyStatement> = match validation {
  Ok(id) => 
      vec![IamPolicyStatement {
          effect: Some("Allow".to_string()),
          action: vec!["execute-api:Invoke".to_string()],
          resource: vec![path],
      }],
  Err(e) => {
      println!("token validation failed with error: {:?}", e);
      vec![IamPolicyStatement {
          effect: Some("Deny".to_string()),
          action: vec!["execute-api:Invoke".to_string()],
          resource: vec![path],
      }]
  }
};

let policy = ApiGatewayCustomAuthorizerPolicy {
    version: Some("2012-10-17".to_string()),
    statement,
};

let resp = ApiGatewayCustomAuthorizerResponse {
  principal_id: Some("provider.address".to_string()),
  policy_document: policy,
  context: id,
  usage_identifier_key: None,
};

return Ok(resp);
}