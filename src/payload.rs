/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Payload {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub scp: Vec<String>,
}