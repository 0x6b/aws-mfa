use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about)]
pub struct Args {
    /// Path to AWS credentials file. Defaults to `~/.aws/credentials`
    #[arg(short, long, env = "AWS_SHARED_CREDENTIALS_FILE")]
    pub credentials_path: Option<PathBuf>,

    /// AWS region
    #[arg(short, long, env = "AWS_DEFAULT_REGION", default_value = "ap-northeast-1")]
    pub region: String,

    /// Session duration in seconds
    #[arg(short, long, env = "AWS_SESSION_DURATION", default_value = "43200")]
    pub duration: u32,

    /// 1Password account (e.g., yourcompany.1password.com)
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ACCOUNT")]
    pub op_account: Option<String>,

    /// 1Password item name containing MFA token
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ITEM_NAME")]
    pub op_item_name: Option<String>,
}
