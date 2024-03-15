/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestClaims {
    sub: Option<String>,
    aud: Option<Vec<String>>,
    iss: Option<String>,
    scp: Option<Vec<String>>,
}

impl RequestClaims {
    pub fn default() -> Self { Self { aud: None, iss: None, sub: None, scp: None, } }

    pub fn aud(&self) -> &Option<Vec<String>> { &self.aud }
    pub fn set_aud(&mut self, aud: Option<Vec<String>>) { self.aud = aud; }

    pub fn iss(&self) -> &Option<String> { &self.iss }
    pub fn set_iss(&mut self, iss: Option<String>) { self.iss = iss; }

    pub fn sub(&self) -> &Option<String> { &self.sub }
    pub fn set_sub(&mut self, sub: Option<String>) { self.sub = sub; }

    pub fn scp(&self) -> &Option<Vec<String>> { &self.scp }
    pub fn set_scp(&mut self, scp: Option<Vec<String>>) { self.scp = scp; }
}
