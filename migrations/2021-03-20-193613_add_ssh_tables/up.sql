CREATE TABLE registered_keys (
	fingerprint TEXT PRIMARY KEY NOT NULL,
    user TEXT NOT NULL,
	pin_policy TEXT NULL,
	touch_policy TEXT NULL,
	hsm_serial TEXT NULL,
	firmware TEXT NULL,
	attestation_certificate TEXT NULL,
	attestation_intermediate TEXT NULL
);

CREATE TABLE fingerprint_principal_authorizations (
	fingerprint TEXT NOT NULL,
	principal TEXT NOT NULL,
	PRIMARY KEY (fingerprint, principal)
);

CREATE TABLE fingerprint_host_authorizations (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT PRIMARY KEY NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	principal_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_host_certs BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_user_certs BOOLEAN DEFAULT FALSE NOT NULL,
	max_creation_time BIGINT DEFAULT 10 NOT NULL,
	force_source_ip BOOLEAN DEFAULT FALSE NOT NULL,
	force_command TEXT NULL
);

CREATE TABLE fingerprint_extensions (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL
);