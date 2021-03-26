use crate::key::Key;
use crate::yubikey;

use std::collections::HashMap;
use std::convert::From;

#[derive(Debug)]
pub enum IdentityError {
    ParseError,
    DataError,
    //VerificationError,
    UnknownIdentityType,
}

#[derive(Debug)]
pub enum IdentityType {
    Ssh(Key),
    Mtls,
}

impl From<hex::FromHexError> for IdentityError {
    fn from(_ :hex::FromHexError) -> Self {
        IdentityError::ParseError
    }
}

fn verify_ssh_identity(identities: &HashMap<String, String>, identity_data: &HashMap<String, String>) -> Result<IdentityType, IdentityError> {
    let cert = if let Some(certificate) = identity_data.get("certificate") {
        hex::decode(certificate)?
    } else {
        vec![]
    };

    let intermediate = if let Some(intermediate) = identity_data.get("intermediate_certificate") {
        hex::decode(intermediate)?
    } else {
        vec![]
    };

    let fingerprint = if let Some(fp) = identities.get("key_fingerprint") {
        fp.to_string()
    } else {
        return Err(IdentityError::DataError)
    };

    match yubikey::verify_certificate_chain(&cert, &intermediate) {
        Ok(key) => Ok(IdentityType::Ssh(key)),
        Err(e) => {
            info!("{} has no valid attestation chain: {:?}", fingerprint, e);
            Ok(IdentityType::Ssh(Key {
                fingerprint,
                attestation: None,
            }))
        }
    }
}

/// Called when an editor wants to enroll new identity data, generally on
/// behalf of a user
pub fn verify_identity_data(identities: &HashMap<String, String>, identity_data: &HashMap<String, String>) -> Result<IdentityType, IdentityError> {
    let identity_type = match identity_data.get("type") {
        Some(t) => t,
        None => return Err(IdentityError::UnknownIdentityType),
    };

    match &identity_type.as_str() {
        &"ssh_key" => verify_ssh_identity(identities, identity_data),
        &"mtls" => Ok(IdentityType::Mtls),
        _ => return Err(IdentityError::UnknownIdentityType)
    }
}