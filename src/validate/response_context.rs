/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseContext{
    role: String,
    id: String,
}

impl ResponseContext {
    pub fn new(role: &str, id: &str) -> Self { Self { role: role.to_string(), id: id.to_string() } }

    pub fn role(&self) -> &str { &self.role }
    pub fn id(&self) -> &str { &self.id }

    pub fn to_principal(&self) -> String { [self.role.to_string(), self.id.to_string()].join(":") }
}
