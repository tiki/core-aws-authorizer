/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use aws_lambda_events::apigw::{ApiGatewayCustomAuthorizerRequestTypeRequest, ApiGatewayCustomAuthorizerResponse};
use lambda_runtime::{Error, LambdaEvent};
use super::ValidateResponse;

pub async fn entry(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>
) -> Result<ApiGatewayCustomAuthorizerResponse<ValidateResponse>, Error> {

}

