pub mod schema;
pub mod models;

use crate::author::{
    ModifySshKeyPrincipalsRequest,
    SetPermissionsOnSshKeyRequest,
    SshKey,
    ListRegisteredKeysRequest,
    ListRegisteredKeysResponse,
};


use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::r2d2::{Pool, ConnectionManager};
//use std::time::SystemTime;

use std::collections::HashMap;

use crate::key::Key;

pub struct Database {
    pool: Pool<ConnectionManager<SqliteConnection>>
}

impl From<models::RegisteredSshKey> for SshKey {
    fn from(rsk: models::RegisteredSshKey) -> Self {
        SshKey {
            fingerprint: rsk.fingerprint,
            user: rsk.user,
            pin_policy: rsk.pin_policy.unwrap_or_default(),
            touch_policy: rsk.touch_policy.unwrap_or_default(),
            serial: rsk.hsm_serial.unwrap_or_default(),
            firmware: rsk.firmware.unwrap_or_default(),
            attestation_certificate: rsk.attestation_certificate.unwrap_or_default(),
            attestation_intermediate: rsk.attestation_intermediate.unwrap_or_default(),
            ssh_enabled: rsk.ssh_enabled,
            host_unrestricted: rsk.host_unrestricted,
            principal_unrestricted: rsk.principal_unrestricted,
            can_create_host_certs: rsk.can_create_host_certs,
            can_create_user_certs: rsk.can_create_user_certs,
            max_creation_time: rsk.max_creation_time as u64,
            force_source_ip: rsk.force_source_ip,
            force_command: rsk.force_command.unwrap_or_default(),

        }
    }
}

impl Database {
    pub fn new(database_url: &str) -> Result<Self, String> {
        let pool = Pool::new(ConnectionManager::new(database_url));

        match pool {
            Ok(p) => Ok(Database {pool: p}),
            Err(e) => Err(e.to_string())
        }
    }

    pub fn register_ssh_key(&self, identities: &HashMap<String, String>, key: Key) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };
        
        let mut registered_key = models::RegisteredSshKey {
            fingerprint: key.fingerprint,
            user: identities["mtls_identities"].clone(),
            firmware: None,
            hsm_serial: None,
            touch_policy: None,
            pin_policy: None,
            attestation_certificate: None,
            attestation_intermediate: None,
            ssh_enabled: false,
            host_unrestricted: false,
            principal_unrestricted: false,
            can_create_host_certs: false,
            can_create_user_certs: false,
            max_creation_time: 0,
            force_source_ip: true,
            force_command: None,
        };

        if let Some(attestation) = &key.attestation {
            registered_key.firmware = Some(attestation.firmware.clone());
            registered_key.hsm_serial = Some(attestation.serial.to_string());
            registered_key.touch_policy = Some(attestation.touch_policy.to_string());
            registered_key.pin_policy = Some(attestation.pin_policy.to_string());
            registered_key.attestation_certificate = Some(hex::encode(&attestation.certificate));
            registered_key.attestation_intermediate = Some(hex::encode(&attestation.intermediate));
        }

        let result = {
            use schema::registered_ssh_keys::dsl::*;
            diesel::insert_into(registered_ssh_keys)
                .values(&registered_key)
                .execute(&connection)
        };

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn list_registered_keys(&self, req: ListRegisteredKeysRequest) -> Result<ListRegisteredKeysResponse, ()> {
        let limit = if req.limit > 50 {
            50 as i64
        } else {
            req.limit as i64
        };

        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };

        let keys = {
            use schema::registered_ssh_keys::dsl::*;

            match schema::registered_ssh_keys::table
                .filter(fingerprint.like(format!("%{}%", &req.query)))
                .or_filter(user.like(format!("%{}%", &req.query)))
                .limit(limit)
                .load::<models::RegisteredSshKey>(&connection) {
                    Ok(results) => results,
                    Err(_) => return Err(()),
                }
        };

        Ok(ListRegisteredKeysResponse {
            keys: keys.into_iter().map(|x| x.into()).collect(),
        })
    }

    pub fn set_permissions_on_ssh_key(&self, permissions: SetPermissionsOnSshKeyRequest) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };

        {
            use schema::registered_ssh_keys::dsl::*;
            match diesel::update(registered_ssh_keys)
                .set((
                    ssh_enabled.eq(permissions.ssh_enabled),
                    host_unrestricted.eq(permissions.host_unrestricted),
                    principal_unrestricted.eq(permissions.principal_unrestricted),
                    can_create_host_certs.eq(permissions.can_create_host_certs),
                    can_create_user_certs.eq(permissions.can_create_user_certs),
                    max_creation_time.eq(permissions.max_creation_time as i64),
                    force_source_ip.eq(permissions.force_source_ip),
                    force_command.eq(permissions.force_command),
                ))
                .execute(&connection) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Could not insert new fingerprint permissions: {}", e);
                    Err(())
                },
            }
        }
    }

    pub fn modify_ssh_key_principals(&self, request: ModifySshKeyPrincipalsRequest) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };
        let fingerprint = &request.fingerprint;
        let principals: Vec<models::PrincipalAuthorization> = request.principals.iter().map(|x|
            models::PrincipalAuthorization {
                fingerprint: fingerprint.clone(),
                principal: x.clone(),
            }).collect();

        {
            use schema::fingerprint_principal_authorizations::dsl::*;

            match request.action.as_str() {
                "add" => {
                    // Again Diesel issues where it doesn't support multiple
                    // insert in SQLite
                    let mut errors: Vec<String> = vec![];
                    principals.into_iter().fold(&mut errors, |v, x| {
                        if let Err(e) = diesel::insert_into(fingerprint_principal_authorizations)
                        .values(&x)
                        .execute(&connection) {
                            error!("Error adding principal {}: {}", x.principal, e);
                            v.push(x.principal);
                        }
                        v
                    });
                    match errors.len() {
                        0 => Ok(()),
                        _ => {
                            error!("Errored adding principals {} to {}", errors.join(","), &request.fingerprint);
                            Err(())
                        }
                    }
                },
                "remove" => {
                    match diesel::delete(fingerprint_principal_authorizations)
                        .filter(fingerprint.eq(&fingerprint))
                        .filter(principal.eq_any(&request.principals)).execute(&connection) {
                        Ok(_) => Ok(()),
                        Err(_) => {
                            error!("Error deleting principals from key {}", &request.fingerprint);
                            Err(())
                        }
                    }
                },
                n => {
                    error!("Unknown action on principals tried to be taken: {}", n);
                    Err(())
                }
            }
        }
    }
}