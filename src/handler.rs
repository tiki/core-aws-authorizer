/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use super::validate::{ResponseBuilder, ResponseContext, Validate};
use lambda_runtime::{Error, LambdaEvent};
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse
};

pub async fn entry(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>
) -> Result<ApiGatewayCustomAuthorizerResponse<ResponseContext>, Error> {
    let token = event.payload.headers.get("Authorization")?.to_str()?;
    let audience = event.payload.path.as_ref()?.to_string();
    let validate = Validate::new_from_env(&audience)?;
    let token = validate.decode(token)?;
    let claims = validate.claims(&token)?;
    let sub = claims.custom.sub().clone().ok_or("Missing sub".into())?;
    let res = ResponseContext::from_subject(&sub);
    ResponseBuilder::default()
        .for_event(event)
        .with_result(res)
        .build()
}

