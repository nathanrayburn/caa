use native_tls::Identity;
use std::env;
use dotenv::dotenv;
use base64::decode;
use std::error::Error;
use tokio::io::AsyncWriteExt;
use std::fs;
fn load_key() -> Result<Identity, Box<dyn Error>> {
    let private_key_base64 = env::var("PRIVATE_KEY")?;
    let public_key_base64 = env::var("PUBLIC_KEY")?;
    let public_key_bytes = decode(&public_key_base64)?;
    let private_key_bytes = decode(&private_key_base64)?;
    let identity = Identity::from_pkcs8(&public_key_bytes,&private_key_bytes)?;
    Ok(identity)
}

fn check_env_file() {
    if let Ok(contents) = fs::read_to_string(".env") {
        println!(".env file found with contents:\n{}", contents);
    } else {
        eprintln!(".env file not found or not readable.");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_env_file();
    dotenv()?;

    match env::var("PRIVATE_KEY") {
        Ok(private_key) => println!("PRIVATE_KEY successfully loaded."),
        Err(e) => eprintln!("Failed to load PRIVATE_KEY: {}", e),
    }
    match env::var("PUBLIC_KEY") {
        Ok(public_key) => println!("PUBLIC_KEY successfully loaded."),
        Err(e) => eprintln!("Failed to load PUBLIC_KEY: {}", e),
    }
    let identity = load_key()?;
    let native_acceptor = native_tls::TlsAcceptor::builder(identity).build()?;
    let acceptor = tokio_native_tls::TlsAcceptor::from(native_acceptor);
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
