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

use std::env;

pub mod author {
    tonic::include_proto!("author");
}

pub struct MyAuthor {
    db: database::Database,
}


#[tonic::async_trait]
impl Author for MyAuthor {
    async fn list_registered_keys(
        &self,
        request: Request<ListRegisteredKeysRequest>,
    ) -> Result<Response<ListRegisteredKeysResponse>, Status> {
        let _remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();
        
        match self.db.list_registered_keys(request) {
            Ok(keys) => Ok(Response::new(keys)),
            Err(_) => Err(Status::permission_denied("Could not retrieve key list"))
        }
    }

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

    async fn delete_registered_ssh_key(
        &self,
        request: Request<DeleteRegisteredSshKeyRequest>,
    ) -> Result<Response<DeleteRegisteredSshKeyResponse>, Status> {
        let _remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();

        match &self.db.delete_registered_ssh_key(request) {
            Ok(_) => Ok(Response::new(DeleteRegisteredSshKeyResponse {})),
            Err(_) => Err(Status::permission_denied("Could not delete key")),
        }
    }
    
    async fn modify_ssh_key_authorizations(
        &self,
        request: Request<ModifySshKeyAuthorizationsRequest>,
    ) -> Result<Response<ModifySshKeyAuthorizationsResponse>, Status> {
        let _remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();

        match &self.db.modify_ssh_key_authorizations(request) {
            Ok(_) => Ok(Response::new(ModifySshKeyAuthorizationsResponse {})),
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

        let registered = match identity_type {
            IdentityType::Ssh(key) => self.db.register_ssh_key(&request.identities, key),
            IdentityType::Mtls => Ok(()),
        };

        if let Err(_e) = registered {
            return Err(Status::cancelled("Identity could not be registered at this time. May already be registered."))
        }

        Ok(Response::new(AddIdentityDataResponse {}))
    }

    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let remote_addr = request.remote_addr().unwrap();
        let request = request.into_inner();
        debug!("{:?} requested: {:?}", remote_addr, request);

        match rpc::authorize::authorize(&self.db, &request) {
            Ok(response) => Ok(Response::new(response)),
            Err(_) => Err(Status::permission_denied(""))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let matches = App::new("author")
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
        .tls_config(tls)?
        .add_service(AuthorServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}