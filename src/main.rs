use author::author_server::{Author, AuthorServer};
use author::{AuthorizeRequest, AuthorizeResponse};

use clap::{App, Arg};

use tonic::{transport::Server, Request, Response, Status};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use std::collections::HashMap;

use rand::Rng;

pub mod author {
    tonic::include_proto!("author");
}

#[derive(Default)]
pub struct MyAuthor {}

#[tonic::async_trait]
impl Author for MyAuthor {
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();
        println!("{:?} requested: {:?}", remote_addr, request);

        let request_type = &request.authorization_request["type"];

        match request_type.as_str() {
            "ssh" => {
                let cert_type = &request.authorization_request["cert_type"];
                let mut rng = rand::thread_rng();

                // Hard coded rule: Don't allow creation of host certs
                if cert_type == "host certificate" {
                    return Err(Status::permission_denied("Not allowed to create host certs"));
                }

                // Normally you'd do a bunch of DB look ups here to determine what these values should be
                // but right now just pass them though as proof of concept
                let mut response = HashMap::new();
                response.insert(String::from("valid_before"), request.authorization_request["valid_before"].clone());
                response.insert(String::from("valid_after"), request.authorization_request["valid_after"].clone());
                response.insert(String::from("serial"), rng.gen::<u64>().to_string());
                response.insert(String::from("servers"), request.authorization_request["servers"].clone());
                response.insert(String::from("principals"), request.authorization_request["principals"].clone());
                response.insert(String::from("valid_before"), request.authorization_request["valid_before"].clone());
                response.insert(String::from("valid_after"), request.authorization_request["valid_after"].clone());

                let reply = author::AuthorizeResponse {
                    approval_response: response,
                };

                Ok(Response::new(reply))
            },
            "mtls" => {
                // We don't do anything here other than log a new mTLS cert was issued.
                // Again you could have tonnes of control over this like requiring mTLS certs
                // for a user come from a UUID issued to that user.
                let reply = author::AuthorizeResponse {
                    approval_response: HashMap::new(),
                };

                Ok(Response::new(reply))
            }
            _ => {
                return Err(Status::invalid_argument("Unknown request type"));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("rustica")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Author is a demo authentication orchestrator")
        .arg(
            Arg::new("servercert")
                .about("Path to PEM that contains server public key")
                .long("servercert")
                .short('c')
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("serverkey")
                .about("Path to key that contains server private key")
                .long("serverkey")
                .short('k')
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("cacert")
                .about("The CA to use for mTLS")
                .required(true)
                .long("ca")
                .takes_value(true),
        )
        .get_matches();
    
    let cert = tokio::fs::read(matches.value_of("servercert").unwrap()).await?;
    let key = tokio::fs::read(matches.value_of("serverkey").unwrap()).await?;
    let server_identity = Identity::from_pem(cert, key);

    let client_ca_cert = tokio::fs::read(matches.value_of("cacert").unwrap()).await?;
    let client_ca_cert = Certificate::from_pem(client_ca_cert);

    let tls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_cert);


    let addr = "[::1]:50051".parse().unwrap();
    let auth = MyAuthor::default();

    println!("Author listening on {}", addr);

    Server::builder()
        .tls_config(tls)?
        .add_service(AuthorServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}