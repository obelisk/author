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
