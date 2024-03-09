/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use chrono::Duration;

use crate::{AuthContext, Payload};
use aws_lambda_events::apigw::ApiGatewayCustomAuthorizerRequestTypeRequest;
use jwt_compact::{alg::Es256, jwk::JsonWebKey, prelude::*, Algorithm};
use lambda_runtime::{Error, LambdaEvent};

type PublicKey = <Es256 as Algorithm>::VerifyingKey;

pub fn validate(
    event: &LambdaEvent<ApiGatewayCustomAuthorizerRequestTypeRequest>,
) -> Result<AuthContext, Error> {
    let token: String = event
        .payload
        .headers
        .get("Authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
        .replace("Bearer ", "");

    let endpoint: String = event.payload.path.as_ref().unwrap().to_string();

    let key = r#"{"kty":"EC","use":"sig","crv":"P-256","kid":"0d2dbad0-81f5-4625-94a8-91e839581ac8","x":"vcM5IpNurycR5RbOGueTZAWp-FQfAwGUTVY1YwNli_c","y":"-Ag2sVft6NAcSxkvHc2gS5vcB3bdrB66pDPFuS_6u1U","alg":"ES256"}"#;

    let jwk: JsonWebKey = serde_json::from_str(key)?;
    let public_key = PublicKey::try_from(&jwk)?;
    let token = UntrustedToken::new(&token)?;
    let token: Token<Payload> = Es256.validator(&public_key).validate(&token)?;
    return claims(&token, endpoint);
}

fn claims(token: &Token<Payload>, aud: String) -> Result<AuthContext, Error> {
    let time_options = TimeOptions::from_leeway(Duration::seconds(60));
    token.claims().validate_expiration(&time_options)?;

    if token.claims().not_before.is_some() {
        token.claims().validate_maturity(&time_options)?;
    }

    if !token.claims().custom.aud.contains(&aud) {
        return Err("Invalid AUD claim".into());
    }

    if token.claims().custom.iss != "https://mytiki.com" {
        return Err("Invalid iss claim".into());
    }

    if token.claims().custom.scp.contains(&"publish".to_string()) {
        return Err("Invalid scp claim".into());
    }

    let mut splitter = token.claims().custom.sub.splitn(2, ':');
    let role = splitter.next().unwrap();
    let id = splitter.next().unwrap();

    Ok(AuthContext {
        role: role.to_string(),
        id: id.to_string(),
    })
}

#[cfg(test)]
mod tests {

    use aws_lambda_events::apigw::ApiGatewayCustomAuthorizerRequestTypeRequest;
    use lambda_runtime::LambdaEvent;
    use serde_json;

    use super::validate;

    #[test]
    fn validate_jwt() {
      let context = serde_json::from_str(r#"
        {
            "request_id": "request-id",
            "deadline": 100,
            "invoked_function_arn": "function-arn",
            "xray_trace_id": "trace-id",
            "client_context": {},
            "cognito_identity": {},
            "env_config": {
              "function_name": "function",
              "memory": 0,
              "version": "v1",
              "log_stream": "aaa",
              "log_group": "bbb"
            },
            "function_name": "function"
        }
        "#).expect("Error deserializing context json");
      let payload: ApiGatewayCustomAuthorizerRequestTypeRequest = serde_json::from_str(r#"{
        "type": "REQUEST",
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request",
        "resource": "/request",
        "path": "/request",
        "httpMethod": "GET",
        "headers": {
          "X-AMZ-Date": "20170718T062915Z",
          "Accept": "*/*",
          "Authorization": "Bearer eyJraWQiOiIwZDJkYmFkMC04MWY1LTQ2MjUtOTRhOC05MWU4Mzk1ODFhYzgiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL215dGlraS5jb20iLCJzdWIiOiJwcm92aWRlcjpiNDQwNWY4ZS0zMjIyLTRjYmYtYTc4Ny02OTEyMzdhOGYxYjciLCJhdWQiOiJhY2NvdW50Lm15dGlraS5jb20iLCJzY3AiOlsiYWNjb3VudDpwcm92aWRlciJdLCJleHAiOjE3MDgzNjc5NDAsImlhdCI6MTcwODM2NzM0MH0.IBhfxRwnaTR-uxB3zO65ut3S1L2rFFmJqh9wPClt4N91iJSZl_Pyx7SkkrrOLU1P62295XdloY2ZNx1jhpaEKw",
          "CloudFront-Viewer-Country": "US",
          "CloudFront-Forwarded-Proto": "https",
          "CloudFront-Is-Tablet-Viewer": "false",
          "CloudFront-Is-Mobile-Viewer": "false",
          "User-Agent": "..."
        },
        "queryStringParameters": {
          "QueryString1": "queryValue1"
        },
        "pathParameters": {},
        "stageVariables": {
          "StageVar1": "stageValue1"
        },
        "requestContext": {
          "path": "/request",
          "accountId": "123456789012",
          "resourceId": "05c7jb",
          "stage": "test",
          "requestId": "...",
          "identity": {
            "apiKey": "...",
            "sourceIp": "...",
            "clientCert": {
              "clientCertPem": "CERT_CONTENT",
              "subjectDN": "www.example.com",
              "issuerDN": "Example issuer",
              "serialNumber": "a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1",
              "validity": {
                "notBefore": "May 28 12:30:02 2019 GMT",
                "notAfter": "Aug  5 09:36:04 2021 GMT"
              }
            }
          },
          "resourcePath": "/request",
          "httpMethod": "GET",
          "apiId": "abcdef123"
        }
      }
        "#).expect("Error deserializing payload json");
        validate(&LambdaEvent {
            payload: payload,
            context: context,
        }).expect("JWT Validation error");
    }
}
