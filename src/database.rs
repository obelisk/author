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

impl From<SetPermissionsOnSshKeyRequest> for models::FingerprintPermission {
    fn from(perms: SetPermissionsOnSshKeyRequest) -> Self {
        let force_command = if perms.force_command.len() == 0 {
            None
        } else {
            Some(perms.force_command)
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

        let results = {
            //use schema::registered_keys::dsl::*;
            use schema::*;

            #[derive(Queryable)]
            struct Row {
                fingerprint: String,
                user: String,
                pin_policy: Option<String>,
                touch_policy: Option<String>,
                serial: Option<String>,
                firmware: Option<String>,
                //attestation_certificate: Option<String>,
                //attestation_intermediate: Option<String>,
                host_unrestricted: Option<bool>,
                principal_unrestricted: Option<bool>,
                can_create_host_certs: Option<bool>,
                can_create_user_certs: Option<bool>,
                max_creation_time: Option<i64>,
                force_source_ip: Option<bool>,
                force_command: Option<String>,
            }

            match schema::registered_keys::table
                .filter(registered_keys::fingerprint.like(format!("%{}%", &req.query)))
                .or_filter(registered_keys::user.like(format!("%{}%", &req.query)))
                .left_join(schema::fingerprint_permissions::table.on(registered_keys::fingerprint.eq(fingerprint_permissions::dsl::fingerprint)))
                .limit(limit)
                .select((
                    registered_keys::fingerprint,
                    registered_keys::user,
                    registered_keys::pin_policy,
                    registered_keys::touch_policy,
                    registered_keys::hsm_serial,
                    registered_keys::firmware,
                    //registered_keys::attestation_certificate,
                    //registered_keys::attestation_intermediate,
                    fingerprint_permissions::host_unrestricted.nullable(),
                    fingerprint_permissions::principal_unrestricted.nullable(),
                    fingerprint_permissions::can_create_host_certs.nullable(),
                    fingerprint_permissions::can_create_user_certs.nullable(),
                    fingerprint_permissions::max_creation_time.nullable(),
                    fingerprint_permissions::force_source_ip.nullable(),
                    fingerprint_permissions::force_command.nullable(),
                ))
                .load::<Row>(&connection) {
                    Ok(results) => results,
                    Err(_) => return Err(()),
                }
        };

        // TODO: Bad use of unwrap or default. This should probably be
        // retooled or rethought
        let keys =  results.into_iter().map(|x| {
            SshKey {
                fingerprint: x.fingerprint,
                user: x.user,
                pin_policy: x.pin_policy.unwrap_or_default(),
                touch_policy: x.touch_policy.unwrap_or_default(),
                serial: x.serial.unwrap_or_default(),
                firmware: x.firmware.unwrap_or_default(),
                attestation_certificate: String::new(),
                attestation_intermediate: String::new(),
                host_unrestricted: x.host_unrestricted.unwrap_or_default(),
                principal_unrestricted: x.principal_unrestricted.unwrap_or_default(),
                can_create_host_certs: x.can_create_host_certs.unwrap_or_default(),
                can_create_user_certs: x.can_create_user_certs.unwrap_or_default(),
                max_creation_time: x.max_creation_time.unwrap_or_default() as u64,
                force_source_ip: x.force_source_ip.unwrap_or_default(),
                force_command: x.force_command.unwrap_or_default(),
                extensions: HashMap::new(),
                host_groups: vec![],
                principals: vec![],
            }
        }).collect();


        Ok(ListRegisteredKeysResponse {
            keys,
        })
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