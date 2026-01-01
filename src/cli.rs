use std::path::PathBuf;

use clap::Parser;

/// Command-line arguments for AWS MFA credential updater.
///
/// This application refreshes AWS credentials by obtaining temporary session tokens
/// using Multi-Factor Authentication (MFA). It reads long-term credentials from an
/// AWS credentials file, uses them to authenticate with MFA, and writes the temporary
/// credentials back to the file for use by other AWS tools.
///
/// ## Configuration Priority
///
/// Arguments can be provided via command-line flags or environment variables.
/// Command-line arguments take precedence over environment variables.
///
/// ## Required Credentials File Structure
///
/// The credentials file must contain a `[default-long-term]` section with:
/// - `aws_access_key_id`: Your AWS access key ID
/// - `aws_secret_access_key`: Your AWS secret access key
/// - `aws_mfa_device`: ARN of your MFA device (e.g., `arn:aws:iam::123456789012:mfa/user`)
///
/// ## 1Password Integration
///
/// When both `op_account` and `op_item_name` are provided, the application will
/// attempt to retrieve the MFA token automatically from 1Password using the `op` CLI.
/// If this fails, it falls back to manual token entry via stdin.
#[derive(Parser)]
#[command(author, version, about)]
pub struct Args {
    /// Path to AWS credentials file.
    ///
    /// Specifies the location of the AWS credentials file to read long-term credentials
    /// from and write temporary credentials to. The file must exist and contain a
    /// `[default-long-term]` section with the required AWS credentials.
    ///
    /// **Default**: `~/.aws/credentials` (standard AWS credentials file location)
    ///
    /// **Environment variable**: `AWS_SHARED_CREDENTIALS_FILE`
    #[arg(short, long, env = "AWS_SHARED_CREDENTIALS_FILE")]
    pub credentials_path: Option<PathBuf>,

    /// Session duration in seconds.
    ///
    /// Specifies how long the temporary AWS credentials should remain valid.
    /// AWS allows a maximum duration of 129,600 seconds (36 hours) for MFA sessions.
    ///
    /// **Default**: 43,200 seconds (12 hours)
    ///
    /// **Valid range**: 900 seconds (15 minutes) to 129,600 seconds (36 hours)
    ///
    /// **Environment variable**: `AWS_SESSION_DURATION`
    ///
    /// **Note**: The actual maximum duration may be limited by your AWS account's
    /// maximum session duration setting for the IAM role or user.
    #[arg(short, long, env = "AWS_SESSION_DURATION", default_value = "43200")]
    pub duration: u32,

    /// 1Password account subdomain or URL.
    ///
    /// The 1Password account identifier used to retrieve MFA tokens automatically.
    /// This should be either the account subdomain (e.g., "yourcompany") or the
    /// full URL (e.g., "yourcompany.1password.com").
    ///
    /// **Required for 1Password integration**: Both `op_account` and `op_item_name`
    /// must be provided to enable automatic MFA token retrieval.
    ///
    /// **Prerequisites**:
    /// - 1Password CLI (`op`) must be installed and authenticated
    /// - The specified account must be accessible to the authenticated user
    ///
    /// **Environment variable**: `AWS_MFA_UPDATER_OP_ACCOUNT`
    ///
    /// **Fallback**: If 1Password retrieval fails, the application will prompt
    /// for manual MFA token entry via stdin.
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ACCOUNT")]
    pub op_account: Option<String>,

    /// 1Password item name containing the MFA token.
    ///
    /// The name of the 1Password item that contains the TOTP (Time-based One-Time Password)
    /// for your AWS MFA device. The application will use `op item get --otp` to retrieve
    /// the current 6-digit MFA code from this item.
    ///
    /// **Required for 1Password integration**: Both `op_account` and `op_item_name`
    /// must be provided to enable automatic MFA token retrieval.
    ///
    /// **Item requirements**:
    /// - Must be a 1Password item with TOTP configured
    /// - Must be accessible from the specified account
    /// - Should generate standard 6-digit numeric codes
    ///
    /// **Environment variable**: `AWS_MFA_UPDATER_OP_ITEM_NAME`
    ///
    /// **Validation**: Retrieved tokens must be exactly 6 digits and numeric.
    /// Invalid tokens will cause fallback to manual entry.
    #[arg(long, env = "AWS_MFA_UPDATER_OP_ITEM_NAME")]
    pub op_item_name: Option<String>,
}
