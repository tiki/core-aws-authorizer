/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use std::error::Error;
use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest, ApiGatewayCustomAuthorizerResponse, IamPolicyStatement};
use lambda_runtime::LambdaEvent;
use super::ResponseContext;

#[derive(Debug)]
pub struct ResponseBuilder {
    arn: Option<String>,
    context: Option<ResponseContext>
}

impl ResponseBuilder {
    pub fn default() -> Self { Self { arn: None, context: None } }

    pub fn for_event(mut self, event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>) -> Self {
        self.arn = event.payload.method_arn.clone();
        self
    }

    pub fn with_result(mut self, result: Result<ResponseContext, Box<dyn Error>>) -> Self {
        self.context = result.ok();
        self
    }

    pub fn build(self) -> ApiGatewayCustomAuthorizerResponse<ResponseContext> {
        let statement: Vec<IamPolicyStatement> = match self.context.is_some() && self.arn.is_some() {
            true => vec![
                IamPolicyStatement {
                    effect: Some("Allow".to_string()),
                    action: vec!["execute-api:Invoke".to_string()],
                    resource: vec![self.arn.clone().unwrap()]
                }],
            false => vec![
                IamPolicyStatement {
                    effect: Some("Deny".to_string()),
                    action: vec!["execute-api:Invoke".to_string()],
                    resource: vec![self.arn.clone().unwrap_or("*".to_string())]
                }] 
        };
        let context = self.context.clone().unwrap_or(ResponseContext::default());
        ApiGatewayCustomAuthorizerResponse {
            context: context.clone(),
            usage_identifier_key: None,
            principal_id: Some(context.to_principal()),
            policy_document: ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement
            }
        }
    }
}
