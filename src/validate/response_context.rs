/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use std::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseContext{
    namespace: String,
    id: String,
    scopes: String
}

impl ResponseContext {
    
    pub fn default() -> Self { Self::new("","") }
    pub fn new(namespace: &str, id: &str) -> Self { 
        Self { 
            namespace: namespace.to_string(), 
            id: id.to_string(),
            scopes: "".to_string()
        } 
    }

    pub fn namespace(&self) -> &str { &self.namespace }
    pub fn id(&self) -> &str { &self.id }
    pub fn scopes(&self) -> &String { &self.scopes }
    
    pub fn to_principal(&self) -> String { [self.namespace.to_string(), self.id.to_string()].join(":") }
    pub fn from_subject(subject: &str) -> Result<Self, Box<dyn Error>> {
        let mut split = subject.splitn(2, ':');
        Ok(Self {
            namespace: split.next().ok_or("Subject missing role")?.to_string(),
            id: split.next().ok_or("Subject missing id")?.to_string(),
            scopes: "".to_string()
        })
    }

    pub fn with_scopes(&self, scopes: &mut Vec<String>) -> Self {
      let scp_str = self.scopes.clone();
      let mut scp: Vec<&str> = scp_str.split(" ").collect();
      let mut new_scopes: Vec<&str> = scopes.iter().map(|s| { let s: &str = s; s }).collect();
      scp.append(&mut new_scopes);
      scp.sort_unstable();
      scp.dedup();
      let new_scopes = scp.join(" ");
      self.clone()
    }
}
