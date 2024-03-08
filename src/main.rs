/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

mod iam;
mod jwt;

use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse,
};

use lambda_runtime::{run, service_fn, Error, LambdaEvent};

#[tokio::main]
async fn main() -> Result<(), Error> {

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    run(
      service_fn(
        |event| 
        function_handler(event))
    ).await
}

async fn function_handler(
  event: LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthContext>, Error> {

  let validation = jwt::validate(event);

  return iam::policy(event, validation);
}

struct AuthContext{
  id: String,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_add() {
        assert_eq!(1+2, 3);
    }

    #[test]
    fn test_bad_add() {
        assert_eq!(1+1, 3);
    }
}