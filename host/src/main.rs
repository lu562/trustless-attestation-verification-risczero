use clap::{Parser, ValueEnum};
use std::fs;

mod server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(long, default_value = "127.0.0.1")]
    ip: String,
    #[arg(long, default_value_t = 8088)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    let addr = format!("{}:{}", config.ip, config.port);
    println!("Starting server on {}", addr);
    server::run_server(addr).await
}
