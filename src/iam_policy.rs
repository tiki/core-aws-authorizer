use aws_lambda_events::apigw::{
  ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerResponse, IamPolicyStatement,
};

use crate::{AuthContext, Claims};

pub fn prepare_response(
  validated_token: anyhow::Result<jsonwebtoken::TokenData<Claims>>,
) -> anyhow::Result<ApiGatewayCustomAuthorizerResponse<AuthContext>> {

  let path = format!(
    "arn:aws:execute-api:us-east-2:920781344533:67vm38cq09/*"
  );

  let statement: Vec<IamPolicyStatement> = match validated_token {
    Ok(_) => 
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
    context: AuthContext {
        provider: "provider".to_string(),
        address: "address".to_string()
    },
    usage_identifier_key: None,
  };

  return Ok(resp);
}