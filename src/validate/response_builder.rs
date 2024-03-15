/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use std::error::Error;
use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest, ApiGatewayCustomAuthorizerResponse, IamPolicyStatement};
use lambda_runtime::LambdaEvent;
use super::ResponseContext;

pub struct ResponseBuilder {
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
    result: Result<ResponseContext, Box<dyn Error>>
}

impl ResponseBuilder {
    pub fn default() -> Self { Self::default() }

    pub fn for_event(&mut self, event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>) -> &Self {
        self.event = event;
        self
    }

    pub fn with_result(&mut self, result: Result<ResponseContext, Box<dyn Error>>) -> &Self {
        self.result = result;
        self
    }

    pub fn build(&self) -> Result<ApiGatewayCustomAuthorizerResponse<ResponseContext>, Box<dyn Error>> {
        let arn = self.event.payload.method_arn.as_ref().ok_or("Method ARN missing.")?.to_string();
        let context = self.result.as_ref().unwrap_or(&ResponseContext::new("", ""));
        let statement: Vec<IamPolicyStatement> = self.result.as_ref().map_or_else(
            |_error| {
                vec![IamPolicyStatement {
                    effect: Some("Deny".to_string()),
                    action: vec!["execute-api:Invoke".to_string()],
                    resource: vec![arn]
                }]
            }, |_context| {
                vec![IamPolicyStatement {
                    effect: Some("Allow".to_string()),
                    action: vec!["execute-api:Invoke".to_string()],
                    resource: vec![arn]}]
            });
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
