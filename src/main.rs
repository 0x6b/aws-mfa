//! AWS MFA Token Manager
//!
//! This program automates the process of refreshing AWS temporary credentials using MFA tokens.
//! It supports both automated token retrieval from 1Password and manual token input.
//!
//! The program performs the following operations:
//! 1. Parses command-line arguments for configuration
//! 2. Attempts to retrieve MFA token from 1Password (if configured)
//! 3. Falls back to manual input if 1Password retrieval fails
//! 4. Uses the MFA token to request new temporary AWS credentials
//! 5. Updates the local AWS credentials file with the new session tokens

use std::{io::Write, process::Command};

use anyhow::Result;
use clap::Parser;
use log::{info, warn};

mod cli;
mod credentials;
mod updater;

use cli::Args;
use updater::AwsMfaUpdater;

/// Main entry point for the AWS MFA token manager.
///
/// This function orchestrates the entire MFA credential refresh process:
/// 1. Initializes logging with INFO level filtering
/// 2. Parses command-line arguments
/// 3. Creates an AWS MFA updater instance
/// 4. Retrieves the MFA token (from 1Password or manual input)
/// 5. Updates AWS credentials with the new session tokens
///
/// # Returns
/// * `Ok(())` - If the credential update process completes successfully
/// * `Err(anyhow::Error)` - If any step in the process fails
///
/// # Errors
/// This function will return an error if:
/// * The AWS MFA updater cannot be initialized
/// * MFA token retrieval fails
/// * AWS credential update fails
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with INFO level to provide visibility into the process
    // while avoiding debug noise. Users can override with RUST_LOG environment variable.
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command-line arguments using clap's derive API
    let Args {
        credentials_path,
        duration,
        op_account,
        op_item_name,
    } = Args::parse();

    // Initialize the AWS MFA updater with the specified credentials path and duration
    let updater = AwsMfaUpdater::new(credentials_path, duration)?;
    
    // Retrieve MFA token using the configured method (1Password or manual input)
    let token = get_mfa_token(op_account, op_item_name)?;
    
    // Update AWS credentials with the new session tokens
    updater.update_credentials(&token).await
}

/// Retrieves an MFA token using either 1Password automation or manual user input.
///
/// This function implements a fallback strategy for MFA token retrieval:
/// 1. If 1Password credentials are provided, attempt automated retrieval
/// 2. Validate the retrieved token format (6 digits)
/// 3. Fall back to manual input if automation fails or isn't configured
///
/// # Arguments
/// * `op_account` - Optional 1Password account identifier
/// * `op_item_name` - Optional 1Password item name containing the MFA secret
///
/// # Returns
/// * `Ok(String)` - A valid MFA token (6-digit string)
/// * `Err(anyhow::Error)` - If manual input fails or I/O errors occur
///
/// # Error Handling Pattern
/// This function uses a graceful fallback pattern rather than failing fast:
/// - 1Password command failures are logged as warnings, not errors
/// - Invalid token formats trigger fallback rather than failure
/// - Only I/O errors during manual input cause the function to fail
///
/// # Examples
/// ```
/// // Automated retrieval with 1Password
/// let token = get_mfa_token(Some("work".to_string()), Some("aws-mfa".to_string()))?;
/// 
/// // Manual input fallback
/// let token = get_mfa_token(None, None)?;
/// ```
fn get_mfa_token(op_account: Option<String>, op_item_name: Option<String>) -> Result<String> {
    // Attempt 1Password automation if both account and item are provided
    if let (Some(account), Some(item)) = (op_account, op_item_name) {
        // Execute 1Password CLI command to retrieve OTP
        // Using pattern matching to handle command execution gracefully
        if let Ok(output) = Command::new("op")
            .args(["item", "get", "--account", &account, &item, "--otp"])
            .output()
        {
            // Check if the command executed successfully (exit code 0)
            if output.status.success() {
                let otp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                
                // Validate OTP format: must be exactly 6 ASCII digits
                // This prevents invalid tokens from being used and provides early validation
                if otp.len() == 6 && otp.chars().all(|c| c.is_ascii_digit()) {
                    info!("Retrieved MFA token from 1Password");
                    return Ok(otp);
                }
            }
        }
        // Log fallback as warning to inform user of automation failure
        // This is not an error condition, just degraded functionality
        warn!("Failed to get token from 1Password, falling back to manual input");
    }

    // Manual input fallback - prompt user for MFA token
    print!("Enter AWS MFA code for device: ");
    
    // Ensure prompt is immediately visible by flushing stdout buffer
    std::io::stdout().flush()?;
    
    // Read user input from stdin
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    // Return trimmed input to remove trailing newline and whitespace
    Ok(input.trim().to_string())
}
