pub mod schema;
pub mod models;

use crate::author::{
    Authorization,
    ModifySshKeyAuthorizationsRequest,
    SetPermissionsOnSshKeyRequest,
    SshKey,
    ListRegisteredKeysRequest,
    ListRegisteredKeysResponse,
};


use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel::r2d2::{Pool, ConnectionManager};

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
            use_owner_as_principal: rsk.use_owner_as_principal,
            host_unrestricted: rsk.host_unrestricted,
            principal_unrestricted: rsk.principal_unrestricted,
            can_create_host_certs: rsk.can_create_host_certs,
            can_create_user_certs: rsk.can_create_user_certs,
            max_creation_time: rsk.max_creation_time as u64,
            force_source_ip: rsk.force_source_ip,
            use_force_command: rsk.use_force_command,
            force_command: rsk.force_command,
            authorizations: vec![],
        }
    }
}

impl From<models::FingerprintAuthorization> for Authorization {
    fn from(auth: models::FingerprintAuthorization) -> Self {
        Authorization {
            auth_type: auth.type_,
            resource: auth.resource, 
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
            use_owner_as_principal: false,
            host_unrestricted: false,
            principal_unrestricted: false,
            can_create_host_certs: false,
            can_create_user_certs: false,
            max_creation_time: 0,
            force_source_ip: true,
            use_force_command: false,
            force_command: String::new(),
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

        // Only do further investigation of keys if there are 2 or fewer since
        // doing many queries could become expensive. We do two to facilitate
        // building systems that can compare keys.
        if limit <= 2 {
            use schema::fingerprint_authorizations::dsl::*;
            let keys = keys.into_iter().map(|x| {

                let results = match schema::fingerprint_authorizations::table
                .filter(fingerprint.eq(&x.fingerprint))
                .load::<models::FingerprintAuthorization>(&connection) {
                    Ok(results) => results,
                    Err(_) => return x.into(),
                };

                let mut key: SshKey = x.into();
                key.authorizations = results.into_iter().map(|x| x.into()).collect();
                
                key
            }).collect();

            Ok(ListRegisteredKeysResponse {
                keys
            })
        } else {
            Ok(ListRegisteredKeysResponse {
                keys: keys.into_iter().map(|x| x.into()).collect(),
            })
        }
    }

    /// This sets the permissions for an SSH key in Author. It still needs some work
    /// some work as in some isolated cases (adding or removing many tiers and
    /// principals) it could do many inserts.
    pub fn set_permissions_on_ssh_key(&self, permissions: SetPermissionsOnSshKeyRequest) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };

        let fp = permissions.fingerprint;

        let permissions_result = {
            use schema::registered_ssh_keys::dsl::*;
            match diesel::update(registered_ssh_keys)
                .set((
                    ssh_enabled.eq(permissions.ssh_enabled),
                    use_owner_as_principal.eq(permissions.use_owner_as_principal),
                    host_unrestricted.eq(permissions.host_unrestricted),
                    principal_unrestricted.eq(permissions.principal_unrestricted),
                    can_create_host_certs.eq(permissions.can_create_host_certs),
                    can_create_user_certs.eq(permissions.can_create_user_certs),
                    max_creation_time.eq(permissions.max_creation_time as i64),
                    force_source_ip.eq(permissions.force_source_ip),
                    use_force_command.eq(&permissions.use_force_command),
                    force_command.eq(&permissions.force_command),
                ))
                .execute(&connection) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Could not insert new fingerprint permissions: {}", e);
                    Err(())
                },
            }
        };

        // Because PROST! doesn't do optional types and just casts to default,
        // can't tell the difference between remove all authorizations (passing
        // and empty array) or don't touch them (not sending an array). So
        // we have this boolean and will only update them if it's set to true
        if !permissions.set_authorizations {
            return Ok(())
        }

        {
            use schema::fingerprint_authorizations::dsl::*;
            // Remove all previous authorizations.
            match diesel::delete(fingerprint_authorizations)
            .filter(fingerprint.eq(&fp))
            .execute(&connection) {
                Ok(_) => Ok(()),
                Err(_) => {
                    error!("Error deleting principals from key {}", &fp);
                    Err(())
                }
            }.unwrap();
        }
        self.set_identity_authorizations(fp.as_str(), "add", &permissions.authorizations)
    }

    fn set_identity_authorizations(&self, fingerprint: &str, action: &str, authorizations: &[Authorization]) -> Result<(), ()> {
        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };

        let authorizations: Vec<models::FingerprintAuthorization> = authorizations.iter().map(|x|
            models::FingerprintAuthorization {
                fingerprint: fingerprint.to_string(),
                type_: x.auth_type.clone(),
                resource: x.resource.clone(),
            }).collect();
        
        {
            use schema::fingerprint_authorizations::dsl::*;
            
            // This could probably use some clean up but what it does is
            // fold the authorizations array into the relevant inserts or
            // deletes
            let mut errors: Vec<(String, String)> = vec![];
            let errors = authorizations.into_iter().fold(&mut errors, |y, x| {
                if &action == &"add" {
                    if let Err(_) = diesel::insert_into(fingerprint_authorizations)
                    .values(&x)
                    .execute(&connection) {
                        y.push((x.type_, x.resource));
                    }
                } else {
                    if let Err(_) = diesel::delete(fingerprint_authorizations)
                        .filter(fingerprint.eq(&fingerprint))
                        .filter(type_.eq(&x.type_))
                        .filter(resource.eq(&x.resource))
                        .execute(&connection) {
                            y.push((x.type_, x.resource));
                        }
                    }
                    y
                }
            );
            match errors.len() {
                0 => Ok(()),
                _ => {
                    Err(())
                }
            }
        }
    }
    
    pub fn modify_ssh_key_authorizations(&self, request: ModifySshKeyAuthorizationsRequest) -> Result<(), ()> {
        self.set_identity_authorizations(request.fingerprint.as_str(), request.action.as_str(), &request.authorizations)
    }

    /// Take a list of tiers and return all fingerprints that are marked as
    /// belonging to that tier
    pub fn tiers_to_fingerprints(&self, tiers: &[String]) -> Result<Vec<String>, ()> {
        use schema::fingerprint_authorizations::dsl::*;

        let connection = match self.pool.get() {
            Ok(conn) => conn,
            Err(_e) => return Err(()),
        };

        match schema::fingerprint_authorizations::table
        .filter(type_.eq("in_tier"))
        .filter(resource.eq_any(tiers))
        .load::<models::FingerprintAuthorization>(&connection) {
            Ok(results) => Ok(results.into_iter().map(|x| x.fingerprint).collect()),
            Err(_) => return Err(()),
        }
    }
}