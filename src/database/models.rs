use super::schema::*;

#[derive(Queryable, Insertable)]
#[table_name = "registered_keys"]
pub struct RegisteredKey {
    pub fingerprint: String,
    pub user: String,
    pub pin_policy: Option<String>,
    pub touch_policy: Option<String>,
    pub hsm_serial: Option<String>,
    pub firmware: Option<String>,
    pub attestation_certificate: Option<String>,
    pub attestation_intermediate: Option<String>,
}

#[derive(Queryable, Insertable)]
#[table_name = "fingerprint_permissions"]
pub struct FingerprintPermission {
    pub fingerprint: String,
    pub host_unrestricted: bool,
	pub principal_unrestricted: bool,
	pub can_create_host_certs: bool,
	pub can_create_user_certs: bool,
	pub max_creation_time: i64,
	pub force_source_ip: bool,
	pub force_command: Option<String>,
}

#[derive(Queryable, Insertable)]
#[table_name = "fingerprint_principal_authorizations"]
pub struct PrincipalAuthorization {
    pub fingerprint: String,
    pub principal: String,
}