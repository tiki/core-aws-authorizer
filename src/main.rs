/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

mod handler;
mod validate;

use tracing::event;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();
    run(service_fn(catch_all)).await
}

async fn catch_all(
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>
) -> Result<ApiGatewayCustomAuthorizerResponse<validate::ResponseContext>, Error> {
    tracing::debug!("{:?}", event);
    handler::entry(event).await.map_err(|err| {
        tracing::error!("{:?}", err);
        err
    })
}
