/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

#[derive(Deserialize, Serialize)]
pub struct Claims {
    aud: String,
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
    scp: Vec<String>,
}
