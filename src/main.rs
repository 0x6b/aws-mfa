use std::{io::Write, process::Command};

use anyhow::Result;
use clap::Parser;
use log::{info, warn};

mod cli;
mod credentials;
mod updater;

use cli::Args;
use updater::AwsMfaUpdater;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let Args {
        credentials_path,
        duration,
        op_account,
        op_item_name,
    } = Args::parse();

    let updater = AwsMfaUpdater::new(credentials_path, duration).await?;
    let token = get_mfa_token(op_account, op_item_name)?;
    updater.update_credentials(&token).await
}

fn get_mfa_token(op_account: Option<String>, op_item_name: Option<String>) -> Result<String> {
    if let (Some(account), Some(item)) = (op_account, op_item_name) {
        if let Ok(output) = Command::new("op")
            .args(["item", "get", "--account", &account, &item, "--otp"])
            .output()
        {
            if output.status.success() {
                let otp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if otp.len() == 6 && otp.chars().all(|c| c.is_ascii_digit()) {
                    info!("Retrieved MFA token from 1Password");
                    return Ok(otp);
                }
            }
        }
        warn!("Failed to get token from 1Password, falling back to manual input");
    }

    print!("Enter AWS MFA code for device: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
