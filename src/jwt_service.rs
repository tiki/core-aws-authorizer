use crate::{Claims, JWTK};

pub fn validate_token(
    token: &String,
) -> anyhow::Result<jsonwebtoken::TokenData<Claims>> {

    // let token_header: jsonwebtoken::Header = jsonwebtoken::decode_header(&token)?;
    
    // let kid: String = token_header.kid.unwrap();

    let public_key_to_use = JWTK {
      kty: "EC".to_string(),
      uses: "sig".to_string(),
      kid: "0d2dbad0-81f5-4625-94a8-91e839581ac8".to_string(),
      e: "vcM5IpNurycR5RbOGueTZAWp-FQfAwGUTVY1YwNli_c".to_string(),
      n: "-Ag2sVft6NAcSxkvHc2gS5vcB3bdrB66pDPFuS_6u1U".to_string(),
      alg: "ES256".to_string(),
    };
    
    let decoding_key: jsonwebtoken::DecodingKey =
        jsonwebtoken::DecodingKey::from_rsa_components(&public_key_to_use.n, &public_key_to_use.e)?;
    
    // let expected_aud: String = "api://default".to_string();
    
    let validation: jsonwebtoken::Validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    
    let token_data: jsonwebtoken::TokenData<Claims> = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation)?;
    
    return Ok(token_data);
}