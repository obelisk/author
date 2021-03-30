use crate::author::{
    Authorization,
    AuthorizeRequest,
    AuthorizeResponse,
    ListRegisteredKeysRequest,
};

use crate::database::Database;

use rand::Rng;

use std::collections::HashMap;
use std::time::SystemTime;

fn authorize_ssh(db: &Database, request: &AuthorizeRequest) -> Result<AuthorizeResponse, ()> {
    let cert_type = &request.authorization_request["cert_type"];
    let fingerprint = &request.identities["key_fingerprint"];

    let mut rng = rand::thread_rng();

    let key_lookup = ListRegisteredKeysRequest {
        identities: HashMap::new(),
        query: fingerprint.clone(),
        limit: 1,
    };

    let key = match db.list_registered_keys(key_lookup) {
        Ok(k) => {
            match k.keys.into_iter().next() {
                Some(key) => key,
                None => return Err(())
            }
        },
        Err(_) => return Err(())
    };

    if !key.ssh_enabled {
        return Err(())
    }

    if cert_type == "host certificate" && !key.can_create_host_certs {
        return Err(())
    }

    if cert_type == "user certificate" && !key.can_create_user_certs {
        return Err(())
    }

    let mut response = HashMap::new();

    let tiers: Vec<String> = key.authorizations.iter()
        .filter(|x| x.auth_type == "ssh_access")
        .map(|x| x.resource.clone())
        .collect();
    
    let mut principals: Vec<String> = key.authorizations.iter()
        .filter(|x| x.auth_type == "principal")
        .map(|x| x.resource.clone())
        .collect();
    
    if key.use_owner_as_principal {
        principals.push(key.user);
    }

    let authorized_fingerprints = match db.tiers_to_fingerprints(&tiers) {
        Ok(authorized_fingerprints) => authorized_fingerprints,
        Err(_) => return Err(())
    };
    response.insert(String::from("authorized_fingerprints"), authorized_fingerprints.join(","));

    let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(ts) => ts.as_secs(),
        Err(_e) => 0xFFFFFFFFFFFFFFFF,
    };
    response.insert(String::from("valid_after"), format!("{}", current_timestamp));
    response.insert(String::from("valid_before"), format!("{}", current_timestamp + key.max_creation_time));
    response.insert(String::from("serial"), rng.gen::<u64>().to_string());
    response.insert(String::from("principals"), principals.join(","));

    Ok(AuthorizeResponse {
        approval_response: response,
    })
}

pub fn authorize(db: &Database, request: &AuthorizeRequest) -> Result<AuthorizeResponse, ()> {
    let request_type = &request.authorization_request["type"];

    match request_type.as_str() {
        "ssh" => {
            authorize_ssh(db, request)
        },
        "mtls" => {
            // We don't do anything here other than log a new mTLS cert was issued.
            // Again you could have tonnes of control over this like requiring mTLS certs
            // for a user come from a UUID issued to that user.
            Ok(AuthorizeResponse {
                approval_response: HashMap::new(),
            })
        }
        _ => {
            return Err(());
        }
    }
}