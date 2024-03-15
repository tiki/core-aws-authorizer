/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

mod response_context;
pub use response_context::ResponseContext;
mod request_claims;
pub  use request_claims::RequestClaims;

mod response_builder;
pub use response_builder::ResponseBuilder;

use std::env;
use std::error::Error;
use chrono::TimeDelta;
use jwt_compact::{alg::Es256, Algorithm, AlgorithmExt, jwk::JsonWebKey, TimeOptions, Token, UntrustedToken, Claims};

pub type PublicKey = <Es256 as Algorithm>::VerifyingKey;

pub struct Validate {
    public_key: PublicKey,
    audience: String,
    issuer: String
}

impl Validate {
    pub fn new(key: PublicKey, issuer: &str, audience: &str) -> Self {
        Self {
            public_key: key,
            issuer: issuer.to_string(),
            audience: audience.to_string()
        }
    }

    pub fn new_from_jwk(jwk: &str, issuer: &str, audience: &str) -> Result<Self, Box<dyn Error>> {
        let jwk: JsonWebKey = serde_json::from_str(jwk)?;
        let public_key = PublicKey::try_from(&jwk)?;
        Ok(Self::new(public_key, issuer, audience))
    }

    pub fn new_from_env(audience: &str) -> Result<Self, Box<dyn Error>> {
        let key = match env::var("TIKI_JWK") {
            Ok(key) => key,
            Err(_) => panic!("Please set TIKI_JWK"),
        };
        let issuer = match env::var("TIKI_ISSUER") {
            Ok(issuer) => issuer,
            Err(_) => "https://mytiki.com",
        };
        Self::new_from_jwk(&key, &issuer, audience)
    }

    pub fn decode(&self, token: &str) -> Result<Token<RequestClaims>, Box<dyn Error>> {
        let token = token.replace("Bearer ", "");
        let token = UntrustedToken::new(&token)?;
        Ok(Es256.validator(&self.public_key).validate(&token)?)
    }

    pub fn claims(&self, token: &Token<RequestClaims>) -> Result<&Claims<RequestClaims>, Box<dyn Error>> {
        let time_options = TimeOptions::from_leeway(TimeDelta::try_seconds(60)?);

        if token.claims().expiration.is_some() { token.claims().validate_expiration(&time_options)?; }
        if token.claims().not_before.is_some() { token.claims().validate_maturity(&time_options)?; }

        if token.claims().custom.aud().is_some() {
            let aud = token.claims().custom.aud().clone().unwrap();
            if !aud.contains(&self.audience) { return Err("Invalid aud claim".into()) }
        }

        if token.claims().custom.iss().is_some() {
            let iss = token.claims().custom.iss().clone().unwrap();
            if iss != self.issuer { return Err("Invalid iss claim".into()); }
        }

        // TODO fix SCP claim validation.
        // if token.claims().custom.scp.contains(&"publish".to_string()) {
        //     return Err("Invalid scp claim".into());
        // }
        Ok(token.claims())
    }
}
