use super::schema::registered_keys;

#[derive(Insertable)]
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