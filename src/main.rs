use tonic::{transport::Server, Request, Response, Status};

use govna::govna_server::{Govna, GovnaServer};
use govna::{AuthorizeRequest, AuthorizeResponse};

use std::collections::HashMap;

use rand::Rng;

pub mod govna {
    tonic::include_proto!("govna");
}

#[derive(Default)]
pub struct MyGovna {}

#[tonic::async_trait]
impl Govna for MyGovna {
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

                let reply = govna::AuthorizeResponse {
                    approval_response: response,
                };

                Ok(Response::new(reply))
            },
            "mtls" => {
                // We don't do anything here other than log a new mTLS cert was issued.
                // Again you could have tonnes of control over this like requiring mTLS certs
                // for a user come from a UUID issued to that user.
                let reply = govna::AuthorizeResponse {
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
    let addr = "[::1]:50051".parse().unwrap();
    let greeter = MyGovna::default();

    println!("Govna listening on {}", addr);

    Server::builder()
        .add_service(GovnaServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}