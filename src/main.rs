/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

mod iam;
mod jwt;
mod auth_context;
mod payload;
mod handler;

mod validate;
use validate::ValidateResponse;

use auth_context::AuthContext;

use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};

use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use tracing::event;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();
    run(service_fn(catch_all)).await
}

async fn function_handler(
  event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthContext>, Error> {

  let validation = jwt::validate(&event);

  return Ok(iam::policy(&event, validation));
}


async fn catch_all(event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>) -> Result<ApiGatewayCustomAuthorizerResponse<ValidateResponse>, Error> {
    tracing::debug!("{:?}", event);
    handler::entry(event).await.map_err(|err| {
        tracing::error!("{:?}", err);
        err
    })
}
