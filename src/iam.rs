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
  event: &LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>, 
  validation: Result<AuthContext, Error>
) -> ApiGatewayCustomAuthorizerResponse<AuthContext> {

  let arn = event.payload.method_arn.as_ref().unwrap().to_string();

  let auth_context: AuthContext = match validation {
    Ok(ref context) => context.clone(),
    Err(_) => AuthContext { role:"".to_string(), id: "".to_string()}
  };

  let statement: Vec<IamPolicyStatement> = match validation {
    Ok(_) => 
        vec![IamPolicyStatement {
            effect: Some("Allow".to_string()),
            action: vec!["execute-api:Invoke".to_string()],
            resource: vec![arn],
        }],
    Err(_) => {
        vec![IamPolicyStatement {
            effect: Some("Deny".to_string()),
            action: vec!["execute-api:Invoke".to_string()],
            resource: vec![arn],
        }]
    }
  };

  let policy = ApiGatewayCustomAuthorizerPolicy {
      version: Some("2012-10-17".to_string()),
      statement,
  };

  return ApiGatewayCustomAuthorizerResponse {
    principal_id: Some("provider.address".to_string()),
    policy_document: policy,
    context: auth_context,
    usage_identifier_key: None,
  };
}