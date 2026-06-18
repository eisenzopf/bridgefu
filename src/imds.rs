//! Minimal IMDSv2 client — fetch the instance's public IPv4 (the Elastic IP)
//! so `advertised_ip: auto` / `media_public_ip: auto` self-wire on EC2.
//!
//! Hand-rolled HTTP/1.1 over the link-local metadata endpoint (plain HTTP, no
//! TLS) to avoid pulling an HTTP-client dependency. Bounded by a short timeout
//! so it fails fast when not running on EC2.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IMDS: &str = "169.254.169.254:80";
const TIMEOUT: Duration = Duration::from_secs(2);

/// Return the instance public IPv4 via IMDSv2 (token-authenticated).
pub async fn public_ipv4() -> Result<String> {
    tokio::time::timeout(TIMEOUT, fetch_public_ipv4())
        .await
        .map_err(|_| anyhow!("IMDS request timed out (not on EC2?)"))?
}

async fn fetch_public_ipv4() -> Result<String> {
    let token = put_token().await.context("IMDSv2 token")?;
    let req = format!(
        "GET /latest/meta-data/public-ipv4 HTTP/1.1\r\n\
         Host: 169.254.169.254\r\n\
         X-aws-ec2-metadata-token: {token}\r\n\
         Connection: close\r\n\r\n"
    );
    let body = http_roundtrip(&req).await.context("IMDS public-ipv4")?;
    let ip = body.trim().to_string();
    if ip.is_empty() {
        return Err(anyhow!("IMDS returned empty public-ipv4"));
    }
    Ok(ip)
}

async fn put_token() -> Result<String> {
    let req = "PUT /latest/api/token HTTP/1.1\r\n\
               Host: 169.254.169.254\r\n\
               X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\
               Connection: close\r\n\r\n";
    Ok(http_roundtrip(req).await?.trim().to_string())
}

/// Send a raw HTTP/1.1 request to IMDS and return the response body (everything
/// after the header/body separator). Responses are tiny and `Connection: close`.
async fn http_roundtrip(request: &str) -> Result<String> {
    let mut stream = TcpStream::connect(IMDS).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await?;
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
        .to_string();
    Ok(body)
}
