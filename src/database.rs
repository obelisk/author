pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::r2d2::{Pool, ConnectionManager};
//use std::time::SystemTime;

use std::collections::HashMap;

use crate::key::Key;

pub struct Database {
    pool: Pool<ConnectionManager<SqliteConnection>>
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
}