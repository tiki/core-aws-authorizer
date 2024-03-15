/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use std::error::Error;
use super::validate::{ResponseBuilder, ResponseContext, Validate};
use lambda_runtime::LambdaEvent;
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse
};

pub async fn entry(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>
) -> Result<ApiGatewayCustomAuthorizerResponse<ResponseContext>, Box<dyn Error>> {
    let token = event.payload.headers.get("Authorization").ok_or("No authorization header")?.to_str()?;
    let audience = event.payload.path.as_ref().ok_or("No event path")?.to_string();
    let validate = Validate::new_from_env(&audience)?;
    let token = validate.decode(token)?;
    let claims = validate.claims(&token)?;
    let sub = claims.custom.sub().clone().ok_or("Missing sub")?;
    let res = ResponseContext::from_subject(&sub);
    ResponseBuilder::default().for_event(event).with_result(res).build()
}

