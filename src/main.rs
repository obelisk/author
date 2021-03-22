#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;

mod database;
mod key;
mod rpc;
mod yubikey;

use rpc::{
    identity::{self, IdentityType},
};

use author::author_server::{Author, AuthorServer};
use author::*;

use clap::{App, Arg};
use database::Database;
use dotenv::dotenv;

use tonic::{transport::Server, Request, Response, Status};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

use std::collections::HashMap;
use std::env;
use rand::Rng;

pub mod author {
    tonic::include_proto!("author");
}

pub struct MyAuthor {
    db: database::Database,
}


#[tonic::async_trait]
impl Author for MyAuthor {
    async fn set_permissions_on_ssh_key(
        &self,
        request: Request<SetPermissionsOnSshKeyRequest>,
    ) -> Result<Response<SetPermissionsOnSshKeyResponse>, Status> {
        let _remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();

        match &self.db.set_permissions_on_ssh_key(request) {
            Ok(_) => Ok(Response::new(SetPermissionsOnSshKeyResponse {})),
            Err(_) => Err(Status::permission_denied("Could not set permissions on key")),
        }
    }

    async fn modify_ssh_key_principals(
        &self,
        request: Request<ModifySshKeyPrincipalsRequest>,
    ) -> Result<Response<ModifySshKeyPrincipalsResponse>, Status> {
        let _remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();

        match &self.db.modify_ssh_key_principals(request) {
            Ok(_) => Ok(Response::new(ModifySshKeyPrincipalsResponse {})),
            Err(_) => Err(Status::permission_denied("Could not set principals on key")),
        }
    }

    async fn add_identity_data(
        &self,
        request: Request<AddIdentityDataRequest>,
    ) -> Result<Response<AddIdentityDataResponse>, Status> {
        let request = request.into_inner();

        let identity_type = match identity::verify_identity_data(&request.identities, &request.identity_data) {
            Ok(identity) => identity,
            Err(e) => return Err(Status::cancelled(format!("Could not add identity: {:?}", e))),
        };
        debug!("Good to add identity");

        let registered = match identity_type {
            IdentityType::Ssh(key) => self.db.register_ssh_key(&request.identities, key),
            IdentityType::Mtls => Ok(()),
        };

        if let Err(_e) = registered {
            return Err(Status::cancelled("Identity could not be registered at this time"))
        }

        Ok(Response::new(AddIdentityDataResponse {}))
    }

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
    env_logger::init();
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
        .arg(
            Arg::new("listenaddress")
                .about("The CA to use for mTLS")
                .short('l')
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

    let addr = matches.value_of("listenaddress").unwrap_or("[::1]:50051").parse().unwrap();
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let db = match Database::new(&database_url) {
        Ok(db) => db,
        Err(_) => panic!("Could not connect to database: {}", &database_url),
    };

    let auth = MyAuthor {
        db
    };

    println!("Author listening on {}", addr);
    Server::builder()
        //.tls_config(tls)?
        .add_service(AuthorServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}