//! Command-line interface definitions.

use std::path::PathBuf;

use clap::Parser;

/// AWS MFA credential updater.
///
/// Refreshes AWS credentials by obtaining temporary session tokens using MFA.
/// Reads long-term credentials from `[default-long-term]` profile and writes
/// temporary credentials to `[default]` profile.
#[derive(Parser)]
#[command(author, version, about)]
pub struct Args {
    /// Path to AWS credentials file [default: ~/.aws/credentials]
    #[arg(short, long, env = "AWS_SHARED_CREDENTIALS_FILE")]
    pub credentials_path: Option<PathBuf>,

    /// Session duration in seconds (900-129600)
    #[arg(short, long, env = "AWS_SESSION_DURATION", default_value = "43200")]
    pub duration: u32,

    /// 1Password account for automatic MFA token retrieval
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ACCOUNT")]
    pub op_account: Option<String>,

    /// 1Password item name containing the TOTP
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ITEM_NAME")]
    pub op_item_name: Option<String>,
}
