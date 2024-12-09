use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsConnector, rustls::ClientConfig};
use webpki_roots::TLS_SERVER_ROOTS;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8080";
    let domain = "localhost"; // Use the domain or IP that matches the certificate

    // Load the root certificates for the client
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    // Connect to the server
    let stream = TcpStream::connect(addr).await?;
    let mut tls_stream = connector.connect(domain.try_into()?, stream).await?;
    println!("Connected to server via TLS!");

    // Send and receive data
    tls_stream.write_all(b"Hello, TLS server!").await?;
    println!("Message sent to server.");

    let mut buf = vec![0; 1024];
    let n = tls_stream.read(&mut buf).await?;
    println!("Received from server: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
