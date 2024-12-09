use native_tls::{Identity};
use std::env;
use base64::{decode};
use std::error::Error;

fn load_key() -> Result<Identity, Box<dyn Error>> {
    // Get the base64-encoded private key from the environment variable
    let private_key_base64 = env::var("PRIVATE_KEY")?;
    
    // Decode the base64-encoded private key
    let private_key_bytes = decode(&private_key_base64)?;
    
    // Create the TLS identity (assuming it's a PEM-formatted private key)
    let identity = Identity::from_pkcs12(&private_key_bytes, "password")?;
    
    Ok(identity)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the server's identity
    let identity = load_key()?;

    // Create a TLS acceptor
    let native_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
    let acceptor = tokio_native_tls::TlsAcceptor::from(native_acceptor);

    // Create a TCP listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:12345").await?;
    println!("Server listening on 127.0.0.1:12345");

    loop {
        let (socket, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(mut tls_stream) => {
                    if let Err(e) = tls_stream.write_all(b"Hello from server!").await {
                        eprintln!("Failed to write to stream: {}", e);
                    }
                    if let Err(e) = tls_stream.shutdown().await {
                        eprintln!("Failed to shut down stream: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}
