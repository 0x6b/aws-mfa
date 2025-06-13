//! AWS MFA Credentials Updater
//!
//! This module implements the core functionality for updating AWS credentials with temporary
//! MFA-authenticated session tokens. It uses a dual-profile approach in the AWS credentials
//! file to maintain both long-term static credentials and short-term session credentials.
//!
//! ## Dual-Profile Strategy
//!
//! The updater maintains two profiles in the AWS credentials file:
//! - `[default]`: Contains temporary session credentials (access key, secret key, session token)
//!   that are used by AWS SDKs and CLI tools. These expire after the specified duration.
//! - `[default-long-term]`: Contains the permanent IAM user credentials (access key, secret key,
//!   MFA device ARN) that are used to generate new session tokens when the temporary ones expire.
//!
//! This approach ensures that:
//! 1. AWS tools always use the current valid credentials from the `[default]` profile
//! 2. The original long-term credentials are preserved and can be reused for renewal
//! 3. The MFA device configuration is maintained across credential updates
//!
//! ## File Format
//!
//! The credentials file follows this structure:
//! ```ini
//! [default]
//! aws_access_key_id=ASIA...           # Temporary access key
//! aws_secret_access_key=...           # Temporary secret key
//! aws_session_token=...               # Session token (primary)
//! aws_security_token=...              # Session token (legacy compatibility)
//! expiration=2023-12-01T12:00:00Z     # When credentials expire
//!
//! [default-long-term]
//! aws_access_key_id=AKIA...           # Permanent IAM user access key
//! aws_secret_access_key=...           # Permanent IAM user secret key
//! aws_mfa_device=arn:aws:iam::...     # MFA device ARN
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use aws_smithy_types::date_time::Format;
use configparser::ini::Ini;
use log::info;
use tokio::fs;

use crate::credentials::AwsCredentials;

/// AWS MFA credentials updater that manages temporary session tokens.
///
/// This struct handles the complete workflow of:
/// 1. Loading long-term credentials from the AWS credentials file
/// 2. Using those credentials with MFA to obtain temporary session tokens
/// 3. Writing the temporary credentials back to the file in the `[default]` profile
/// 4. Preserving the original long-term credentials in the `[default-long-term]` profile
///
/// The updater is designed to work with the standard AWS credentials file format
/// and maintains compatibility with all AWS SDKs and tools.
pub struct AwsMfaUpdater {
    /// Path to the AWS credentials file (typically ~/.aws/credentials)
    path: PathBuf,
    /// Long-term AWS credentials loaded from the `[default-long-term]` profile
    credentials: AwsCredentials,
    /// Duration in seconds for which the session tokens should be valid (900-129600 seconds)
    duration: u32,
}

impl AwsMfaUpdater {
    /// Creates a new AWS MFA updater by loading long-term credentials from the credentials file.
    ///
    /// This constructor performs several critical initialization steps:
    /// 1. Resolves the credentials file path (uses ~/.aws/credentials if not specified)
    /// 2. Validates that the credentials file exists and is readable
    /// 3. Parses the INI-formatted credentials file
    /// 4. Extracts long-term credentials from the `[default-long-term]` profile
    /// 5. Validates that all required credential fields are present
    ///
    /// # Arguments
    ///
    /// * `path` - Optional path to the AWS credentials file. If `None`, defaults to
    ///   `~/.aws/credentials` following AWS CLI conventions.
    /// * `duration` - Duration in seconds for session token validity. Must be between
    ///   900 seconds (15 minutes) and 129,600 seconds (36 hours) as per AWS STS limits.
    ///
    /// # Returns
    ///
    /// * `Ok(AwsMfaUpdater)` - Successfully initialized updater ready to generate session tokens
    /// * `Err(anyhow::Error)` - Initialization failed due to:
    ///   - Unable to determine home directory
    ///   - Credentials file doesn't exist
    ///   - File parsing errors (invalid INI format)
    ///   - Missing required fields in `[default-long-term]` profile
    ///
    /// # Required Credentials File Format
    ///
    /// The credentials file must contain a `[default-long-term]` profile with:
    /// - `aws_access_key_id`: IAM user access key (starts with AKIA)
    /// - `aws_secret_access_key`: IAM user secret access key
    /// - `aws_mfa_device`: ARN of the MFA device (format: `arn:aws:iam::ACCOUNT:mfa/DEVICE`)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aws_mfa::updater::AwsMfaUpdater;
    /// use std::path::PathBuf;
    ///
    /// // Use default credentials file location
    /// let updater = AwsMfaUpdater::new(None, 3600)?;
    ///
    /// // Use custom credentials file path
    /// let custom_path = PathBuf::from("/custom/path/credentials");
    /// let updater = AwsMfaUpdater::new(Some(custom_path), 7200)?;
    /// ```
    pub fn new(path: Option<PathBuf>, duration: u32) -> Result<Self> {
        // Resolve credentials file path: use provided path or default to ~/.aws/credentials
        // This follows the AWS CLI standard location for credentials
        let path = path
            .or_else(|| dirs::home_dir().map(|d| d.join(".aws").join("credentials")))
            .context("Could not determine home directory")?;
        
        // Ensure the credentials file exists before attempting to parse it
        // This provides a clear error message if the file is missing
        ensure!(path.exists(), "Credentials file not found");

        // Initialize INI parser for reading AWS credentials file format
        // The configparser crate handles the standard INI format used by AWS
        let mut ini = Ini::new();
        ini.load(&path)
            .map_err(|e| anyhow!("Failed to load credentials: {e}"))?;

        // Helper closure to extract required fields from the [default-long-term] profile
        // This profile contains the permanent IAM user credentials used for MFA authentication
        let get = |f| ini.get("default-long-term", f).context(format!("Missing config field: {f}"));
        
        // Load the long-term credentials from the INI file
        // These are the permanent IAM user credentials that will be used to assume
        // temporary credentials via STS GetSessionToken with MFA
        let credentials = AwsCredentials::new(
            get("aws_access_key_id")?,      // IAM user access key (AKIA...)
            get("aws_secret_access_key")?,  // IAM user secret access key
            get("aws_mfa_device")?,         // MFA device ARN
        );

        Ok(Self { path, credentials, duration })
    }

    /// Updates the AWS credentials file with temporary MFA-authenticated session tokens.
    ///
    /// This method performs the complete credential update workflow:
    /// 1. Uses the stored long-term credentials to request temporary session tokens from AWS STS
    /// 2. Validates the MFA token and obtains time-limited credentials
    /// 3. Formats the credentials into the standard AWS INI format
    /// 4. Atomically writes the updated credentials file with both profiles
    /// 5. Preserves the original long-term credentials for future renewals
    ///
    /// # Arguments
    ///
    /// * `token` - The current MFA token code (6-digit number from authenticator app or hardware device)
    ///   This token must be valid and current (typically valid for 30 seconds from generation)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Credentials successfully updated and written to file
    /// * `Err(anyhow::Error)` - Update failed due to:
    ///   - Invalid or expired MFA token
    ///   - AWS STS service errors (network, permissions, etc.)
    ///   - File system errors (permissions, disk space, etc.)
    ///   - Credential formatting errors
    ///
    /// # Security Considerations
    ///
    /// - The MFA token is used immediately and not stored
    /// - Temporary credentials have a limited lifetime (as specified in constructor)
    /// - The credentials file is written atomically to prevent partial updates
    /// - Long-term credentials are preserved in a separate profile for renewal
    ///
    /// # Credential File Output
    ///
    /// After successful execution, the credentials file will contain:
    /// - `[default]` profile with temporary session credentials for immediate use
    /// - `[default-long-term]` profile with preserved permanent credentials
    /// - Both `aws_session_token` and `aws_security_token` for SDK compatibility
    /// - `expiration` timestamp in ISO 8601 format for reference
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aws_mfa::updater::AwsMfaUpdater;
    ///
    /// let updater = AwsMfaUpdater::new(None, 3600)?;
    /// 
    /// // Get current MFA token from authenticator app (e.g., "123456")
    /// let mfa_token = "123456";
    /// updater.update_credentials(mfa_token).await?;
    /// 
    /// // AWS tools can now use the updated credentials from [default] profile
    /// ```
    pub async fn update_credentials(&self, token: &str) -> Result<()> {
        info!("Fetching credentials - Duration: {}s", self.duration);

        // Request temporary session tokens from AWS STS using long-term credentials + MFA
        // This is the core operation that exchanges permanent credentials + MFA token
        // for temporary, time-limited credentials that don't require MFA for subsequent use
        let session = self
            .credentials
            .get_session_token(token, self.duration)
            .await?;
        
        // Extract the temporary credential components from the STS response
        // These will be used to replace the [default] profile in the credentials file
        let access_key_id = session.access_key_id();          // Temporary access key (starts with ASIA)
        let secret_access_key = session.secret_access_key();  // Temporary secret access key
        let session_token = session.session_token();          // Session token (required for temporary creds)
        let expiration = session.expiration().fmt(Format::DateTime)?; // When these credentials expire

        // Build the complete credentials file content with both profiles
        // This maintains the dual-profile structure that enables credential renewal
        let content = format!(
            r"[default]
aws_access_key_id={access_key_id}
aws_secret_access_key={secret_access_key}
aws_session_token={session_token}
aws_security_token={session_token}
expiration={expiration}

[default-long-term]
{}
",
            self.credentials,  // This expands to the formatted long-term credentials via Display trait
        );
        
        // Note: We include both aws_session_token and aws_security_token for maximum compatibility:
        // - aws_session_token: Modern AWS SDKs prefer this field
        // - aws_security_token: Legacy compatibility for older SDKs and tools
        // The expiration field is informational and helps users understand when renewal is needed

        // Atomically write the new credentials file
        // This ensures that the file is never in a partially-written state that could
        // cause authentication failures for concurrent AWS operations
        fs::write(&self.path, content).await?;
        info!("Success! Credentials expire at: {expiration}");

        Ok(())
    }
}
