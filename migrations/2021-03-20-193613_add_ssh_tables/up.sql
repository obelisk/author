CREATE TABLE registered_ssh_keys (
	fingerprint TEXT PRIMARY KEY NOT NULL,
    user TEXT NOT NULL,
	pin_policy TEXT NULL,
	touch_policy TEXT NULL,
	hsm_serial TEXT NULL,
	firmware TEXT NULL,
	attestation_certificate TEXT NULL,
	attestation_intermediate TEXT NULL,
	ssh_enabled BOOLEAN DEFAULT FALSE NOT NULL,
	use_owner_as_principal BOOLEAN DEFAULT FALSE NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	principal_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_host_certs BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_user_certs BOOLEAN DEFAULT FALSE NOT NULL,
	max_creation_time BIGINT DEFAULT 10 NOT NULL,
	force_source_ip BOOLEAN DEFAULT FALSE NOT NULL,
	use_force_command BOOLEAN DEFAULT FALSE NOT NULL,
	force_command TEXT NOT NULL
);

-- Currently a type can be one of:
--	principal: A value that get's inserted into the principals list of a SSH certificate
--	     tier: A tier name that will get translated into a list of fingerprints for allowed servers
CREATE TABLE fingerprint_authorizations (
	fingerprint TEXT NOT NULL,
	type TEXT NOT NULL,
	resource TEXT NOT NULL,
	PRIMARY KEY (fingerprint, type, resource)
);

CREATE TABLE fingerprint_extensions (
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL,
	PRIMARY KEY (fingerprint, extension_name)
);
