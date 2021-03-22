table! {
    fingerprint_extensions (id) {
        id -> BigInt,
        fingerprint -> Text,
        extension_name -> Text,
        extension_value -> Nullable<Text>,
    }
}

table! {
    fingerprint_host_authorizations (id) {
        id -> BigInt,
        fingerprint -> Text,
        hostname -> Text,
    }
}

table! {
    fingerprint_permissions (fingerprint) {
        fingerprint -> Text,
        host_unrestricted -> Bool,
        principal_unrestricted -> Bool,
        can_create_host_certs -> Bool,
        can_create_user_certs -> Bool,
        max_creation_time -> BigInt,
        force_source_ip -> Bool,
        force_command -> Nullable<Text>,
    }
}

table! {
    fingerprint_principal_authorizations (fingerprint, principal) {
        fingerprint -> Text,
        principal -> Text,
    }
}

table! {
    registered_keys (fingerprint) {
        fingerprint -> Text,
        user -> Text,
        pin_policy -> Nullable<Text>,
        touch_policy -> Nullable<Text>,
        hsm_serial -> Nullable<Text>,
        firmware -> Nullable<Text>,
        attestation_certificate -> Nullable<Text>,
        attestation_intermediate -> Nullable<Text>,
    }
}

allow_tables_to_appear_in_same_query!(
    fingerprint_extensions,
    fingerprint_host_authorizations,
    fingerprint_permissions,
    fingerprint_principal_authorizations,
    registered_keys,
);
