//! Reads of credential and policy variables. `std::env::VarError::NotUnicode` carries
//! the value in its `Display` and `Debug`, so `std::env::var(..)` with `.context(..)`
//! or `?` puts a secret into the full error. Every credential or policy variable is read
//! here instead: the refusal names the variable and says whether it is missing or not
//! Unicode, never a byte of the value.
use anyhow::{Result, anyhow};
use std::env::VarError;

/// The variable's value, `None` when it is not set, refused when it is not Unicode.
pub fn optional(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(anyhow!("{name} is not Unicode")),
    }
}

/// The variable's value, refused when it is not set or not Unicode.
pub fn required(name: &str) -> Result<String> {
    optional(name)?.ok_or_else(|| anyhow!("{name} is not set"))
}
