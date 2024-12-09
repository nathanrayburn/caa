use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use rustls::{RootCertStore};
use std::{sync::Arc, env};

fn load_key_from_env() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let private_key_pem = env::var("PRIVATE_KEY")?; // Load private key from environment variable
    let mut reader = std::io::BufReader::new(private_key_pem.as_bytes());
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;

    if keys.is_empty() {
        return Err("No private key found in environment variable.".into());
    }

    Ok(keys[0].clone())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load certificate from file
    let cert_file = std::fs::File::open("cert.pem")?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let cert_chain = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    // Load private key from environment variable
    let private_key = load_key_from_env()?;

    // Configure TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Start the TCP listener
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server running on 127.0.0.1:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Client connected: {}", addr);

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(mut tls_stream) => {
                    println!("TLS session established.");
                    let mut buf = vec![0; 1024];
                    let n = tls_stream.read(&mut buf).await.unwrap();
                    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

                    tls_stream.write_all(b"Hello, TLS client!").await.unwrap();
                }
                Err(e) => eprintln!("TLS handshake failed: {:?}", e),
            }
        });
    }
}
