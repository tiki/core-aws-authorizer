/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

use std::fmt;
use serde::{Deserialize, Deserializer, Serialize, de::Visitor, de::Error, de::SeqAccess, de::value};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestClaims {
    sub: Option<String>,
    #[serde(deserialize_with = "string_or_vec", default)]
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

fn string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where D: Deserializer<'de>
{
    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where E: Error 
        {
            Ok(Some(vec![s.to_owned()]))
        }
        
        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
            where S: SeqAccess<'de>
        {
            let res = Deserialize::deserialize(value::SeqAccessDeserializer::new(seq))?;
            Ok(Some(res))
        }
    }

    deserializer.deserialize_any(StringOrVec)
}
