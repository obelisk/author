// Test program to show how the various APIs of Author work.
// You must disable TLS on Author for this program to work

use author::author_client::{AuthorClient};
use author::*;

use std::collections::HashMap;

pub mod author {
    tonic::include_proto!("author");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_slot = sshcerts::yubikey::SlotId::Retired(sshcerts::yubikey::RetiredSlotId::R11);
    let attestation_slot = sshcerts::yubikey::SlotId::Attestation;
    
    let cert = sshcerts::yubikey::fetch_attestation(cert_slot).unwrap();
    let intermediate_cert = sshcerts::yubikey::fetch_certificate(attestation_slot).unwrap();

    let mut client = AuthorClient::connect("http://[::1]:50051").await?;

    let mut identities = HashMap::new();
    identities.insert(String::from("source_ip"), String::from("127.0.0.1"));
    identities.insert(String::from("key_fingerprint"), String::from("1hVBYYHta/SuXiNUoKd1XsHEDtLEJuX+eEEZC7BZvdY"));
    identities.insert(String::from("mtls_identities"), String::from("CN=testhost"));

    let mut identity_data = HashMap::new();
    identity_data.insert(String::from("type"), String::from("ssh_key"));
    identity_data.insert(String::from("certificate"), hex::encode(cert));
    identity_data.insert(String::from("intermediate_certificate"), hex::encode(intermediate_cert));

    let request = tonic::Request::new(AddIdentityDataRequest {
        identities: identities.clone(),
        identity_data,
    });

    let response = client.add_identity_data(request).await?;
    println!("RESPONSE={:?}", response);

    let request = tonic::Request::new(SetPermissionsOnSshKeyRequest {
        identities: identities.clone(),
        fingerprint: String::from("1hVBYYHta/SuXiNUoKd1XsHEDtLEJuX+eEEZC7BZvdY"),
        host_unrestricted: true,
        principal_unrestricted: true,
        can_create_host_certs: true,
        can_create_user_certs: true,
        max_creation_time: 3600,
        extensions: HashMap::new(),
        force_source_ip: true,
        force_command: String::from(""),
    });

    let response = client.set_permissions_on_ssh_key(request).await?;
    println!("RESPONSE={:?}", response);

    Ok(())
}