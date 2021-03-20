use crate::key::Key;
use crate::yubikey;

use std::collections::HashMap;
use std::convert::From;

#[derive(Debug)]
pub enum IdentityError {
    ParseError,
    VerificationError,
    UnknownIdentityType,
}

#[derive(Debug)]
pub enum IdentityType {
    Ssh(Key),
    Mtls,
}

impl From<hex::FromHexError> for IdentityError {
    fn from(_: hex::FromHexError) -> Self {
        IdentityError::ParseError
    }
}

fn verify_ssh_identity(identity_data: &HashMap<String, String>) -> Result<IdentityType, IdentityError> {
    let cert = hex::decode(&identity_data["certificate"])?;
    let intermediate = hex::decode(&identity_data["intermediate_certificate"])?;

    match yubikey::verify_certificate_chain(&cert, &intermediate) {
        Ok(key) => Ok(IdentityType::Ssh(key)),
        Err(_e) => Err(IdentityError::VerificationError)
    }
}

/// Called when an editor wants to enroll new identity data, generally on
/// behalf of a user
pub fn verify_identity_data(identity_data: &HashMap<String, String>) -> Result<IdentityType, IdentityError> {
    let identity_type = match identity_data.get("type") {
        Some(t) => t,
        None => return Err(IdentityError::UnknownIdentityType),
    };

    match &identity_type.as_str() {
        &"ssh_key" => verify_ssh_identity(identity_data),
        &"mtls" => Ok(IdentityType::Mtls),
        _ => return Err(IdentityError::UnknownIdentityType)
    }
}