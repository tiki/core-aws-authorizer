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
        self.arn = event.payload.method_arn;
        self
    }

    pub fn with_result(mut self, result: Result<ResponseContext, Box<dyn Error>>) -> Self {
        self.context = result.ok();
        self
    }

    pub fn build(self) -> Result<ApiGatewayCustomAuthorizerResponse<ResponseContext>, Box<dyn Error>> {
        let statement: Vec<IamPolicyStatement> = match self.context { 
            Some(_) => vec![
                IamPolicyStatement { 
                    effect: Some("Allow".to_string()), 
                    action: vec!["execute-api:Invoke".to_string()], 
                    resource: vec![self.arn.clone().ok_or("ARN required")?]
                }],
            None => vec![
                IamPolicyStatement { 
                    effect: Some("Deny".to_string()), 
                    action: vec!["execute-api:Invoke".to_string()], 
                    resource: vec![self.arn.clone().ok_or("ARN required")?]
                }] };
        let context = self.context.clone().ok_or("Context required")?;
        let response = ApiGatewayCustomAuthorizerResponse {
            context: context.clone(),
            usage_identifier_key: None,
            principal_id: Some(context.to_principal()),
            policy_document: ApiGatewayCustomAuthorizerPolicy {
                version: Some("2012-10-17".to_string()),
                statement
            }
        };
        Ok(response)
    }
}
