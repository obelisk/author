pub mod schema;
pub mod models;

use crate::author::SetPermissionsOnSshKeyRequest;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::r2d2::{Pool, ConnectionManager};
//use std::time::SystemTime;

use std::collections::HashMap;

use crate::key::Key;

pub struct Database {
    pool: Pool<ConnectionManager<SqliteConnection>>
}

impl From<SetPermissionsOnSshKeyRequest> for models::FingerprintPermission {
    fn from(perms: SetPermissionsOnSshKeyRequest) -> Self {
        let force_command = if perms.force_command.len() == 0 {
            None
        } else {
            Some (perms.force_command)
        };

        models::FingerprintPermission {
            fingerprint: perms.fingerprint,
            host_unrestricted: perms.host_unrestricted,
            principal_unrestricted: perms.principal_unrestricted,
            can_create_host_certs: perms.can_create_host_certs,
            can_create_user_certs: perms.can_create_user_certs,
            max_creation_time: perms.max_creation_time as i64,
            force_source_ip: perms.force_source_ip,
            force_command: force_command,
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
        
        let mut registered_key = models::RegisteredKey {
            fingerprint: key.fingerprint,
            user: identities["mtls_identities"].clone(),
            firmware: None,
            hsm_serial: None,
            touch_policy: None,
            pin_policy: None,
            attestation_certificate: None,
            attestation_intermediate: None,
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
            use schema::registered_keys::dsl::*;
            diesel::insert_into(registered_keys)
                .values(&registered_key)
                .execute(&connection)
        };

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn set_permissions_on_ssh_key(&self, permissions: SetPermissionsOnSshKeyRequest) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };
        
        let row: models::FingerprintPermission = permissions.into();

        {
            use schema::fingerprint_permissions::dsl::*;
            // Annoyingly upsert is not yet released for SQLite so we need to
            // delete the row first, then re-insert it.
            if let Err(e) = diesel::delete(fingerprint_permissions).filter(fingerprint.eq(&row.fingerprint)).execute(&connection) {
                error!("Could not delete old fingerprint permissions: {}", e);
                return Err(())
            }
            match diesel::insert_into(fingerprint_permissions)
                .values(&row)
                .execute(&connection) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Could not insert new fingerprint permissions: {}", e);
                    Err(())
                },
            }
        }
    }
}