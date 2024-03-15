/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

#[allow(unused)]
mod response_context;
pub use response_context::ResponseContext;

#[allow(unused)]
mod request_claims;
pub  use request_claims::RequestClaims;

#[allow(unused)]
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
        let issuer = env::var("TIKI_ISSUER").unwrap_or("https://mytiki.com".to_string());
        Self::new_from_jwk(&key, &issuer, audience)
    }

    pub fn decode(&self, token: &str) -> Result<Token<RequestClaims>, Box<dyn Error>> {
        let token = token.replace("Bearer ", "");
        let token = UntrustedToken::new(&token)?;
        Ok(Es256.validator(&self.public_key).validate(&token)?)
    }

    pub fn claims(&self, token: &Token<RequestClaims>) -> Result<Claims<RequestClaims>, Box<dyn Error>> {
        let time_options = TimeOptions::from_leeway(
            TimeDelta::try_seconds(60).ok_or("TimeDelta::seconds out of bounds")?
        );

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
        
        Ok(token.claims().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::Validate;

    fn jwk() -> &'static str { r#"{"kty":"EC","use":"sig","crv":"P-256","kid":"0d2dbad0-81f5-4625-94a8-91e839581ac8","x":"vcM5IpNurycR5RbOGueTZAWp-FQfAwGUTVY1YwNli_c","y":"-Ag2sVft6NAcSxkvHc2gS5vcB3bdrB66pDPFuS_6u1U","alg":"ES256"}"# }
    fn issuer() -> &'static str { "https://mytiki.com" }


    #[test]
    fn decode_single_aud() {
        let token = "eyJraWQiOiIwZDJkYmFkMC04MWY1LTQ2MjUtOTRhOC05MWU4Mzk1ODFhYzgiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL215dGlraS5jb20iLCJzdWIiOiJ1c2VyOjQzNTI1YzYyLTczNTMtNDI4ZS1iZDJkLTI1NjBhNmI0ZTk2NCIsImF1ZCI6ImFjY291bnQubXl0aWtpLmNvbSIsInNjcCI6WyJhY2NvdW50OmFkbWluIl0sImV4cCI6MTcxMDQ3OTgyMCwiaWF0IjoxNzEwNDc5MjIwfQ.61SSDuaeQT6cnXOXacqq2QbKUs_ZAKEIsSrX_Foct0mstWIcF2pzj38-iHkDj3sYXt7XtKcmH6NPhYS-X4pozg";
        let validate = Validate::new_from_jwk(jwk(), issuer(), "dummy").unwrap();
        let token = validate.decode(token);
        assert_eq!(token.is_ok(), true)
    }

    #[test]
    fn decode_multi_aud() {
        let token = "eyJraWQiOiIwZDJkYmFkMC04MWY1LTQ2MjUtOTRhOC05MWU4Mzk1ODFhYzgiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL215dGlraS5jb20iLCJzdWIiOiJ1c2VyOjQzNTI1YzYyLTczNTMtNDI4ZS1iZDJkLTI1NjBhNmI0ZTk2NCIsImF1ZCI6WyJ0cmFpbC5teXRpa2kuY29tIiwiYWNjb3VudC5teXRpa2kuY29tIl0sInNjcCI6WyJ0cmFpbCIsImFjY291bnQ6YWRtaW4iXSwiZXhwIjoxNzEwNDg0NTIxLCJpYXQiOjE3MTA0ODM5MjF9.ydlc1mb9QrRDfQWmkhZ_ZCHKKO7ZYqFtANS5qjW3JgrnGHjrymf-GFAI47-asaPXg7mA8t9iHiuGG3fq_7K8wg";
        let validate = Validate::new_from_jwk(jwk(), issuer(), "dummy").unwrap();
        let token = validate.decode(token);
        assert_eq!(token.is_ok(), true)
    }
    
    #[test]
    fn decode_no_aud() {
        let token = "eyJraWQiOiIwZDJkYmFkMC04MWY1LTQ2MjUtOTRhOC05MWU4Mzk1ODFhYzgiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL215dGlraS5jb20iLCJzdWIiOiJ1c2VyOjQzNTI1YzYyLTczNTMtNDI4ZS1iZDJkLTI1NjBhNmI0ZTk2NCIsImV4cCI6MTcxMDQ4NDg4MywiaWF0IjoxNzEwNDg0MjgzfQ.Mx5PvH_acQBja0oGsCjxcscXtM5Xp_wwnSvHg586HxHtmM8KEwarnyQ1tBliqrSYXTrwdbsYmzR0r0wePfJFig";
        let validate = Validate::new_from_jwk(jwk(), issuer(), "dummy").unwrap();
        let token = validate.decode(token);
        assert_eq!(token.is_ok(), true)
    }
}
