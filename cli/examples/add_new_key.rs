use author::author_client::{AuthorClient};
use author::*;


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

    let request = tonic::Request::new(AddNewKeyRequest {
        intermediate_cert: intermediate_cert,
        cert: cert,
    });

    let response = client.add_new_key(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}