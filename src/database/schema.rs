table! {
    fingerprint_authorizations (fingerprint, type_, resource) {
        fingerprint -> Text,
        #[sql_name = "type"]
        type_ -> Text,
        resource -> Text,
    }
}

table! {
    fingerprint_extensions (fingerprint, extension_name) {
        fingerprint -> Text,
        extension_name -> Text,
        extension_value -> Nullable<Text>,
    }
}

table! {
    host_tiers (tier, fingerprint) {
        tier -> Text,
        fingerprint -> Text,
    }
}

table! {
    registered_ssh_keys (fingerprint) {
        fingerprint -> Text,
        user -> Text,
        pin_policy -> Nullable<Text>,
        touch_policy -> Nullable<Text>,
        hsm_serial -> Nullable<Text>,
        firmware -> Nullable<Text>,
        attestation_certificate -> Nullable<Text>,
        attestation_intermediate -> Nullable<Text>,
        ssh_enabled -> Bool,
        use_owner_as_principal -> Bool,
        host_unrestricted -> Bool,
        principal_unrestricted -> Bool,
        can_create_host_certs -> Bool,
        can_create_user_certs -> Bool,
        max_creation_time -> BigInt,
        force_source_ip -> Bool,
        force_command -> Nullable<Text>,
    }
}

allow_tables_to_appear_in_same_query!(
    fingerprint_authorizations,
    fingerprint_extensions,
    host_tiers,
    registered_ssh_keys,
);
