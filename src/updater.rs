//! AWS MFA credentials updater.
//!
//! Maintains two profiles in the credentials file:
//! - `[default]`: Temporary session credentials for AWS tools
//! - `[default-long-term]`: Permanent IAM credentials for renewal

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use aws_smithy_types::date_time::Format;
use configparser::ini::Ini;
use dirs::home_dir;
use log::info;
use tokio::fs::write;

use crate::credentials::AwsCredentials;

/// Manages temporary MFA-authenticated session tokens.
pub struct AwsMfaUpdater {
    path: PathBuf,
    credentials: AwsCredentials,
    duration: u32,
}

impl AwsMfaUpdater {
    /// Creates a new updater by loading long-term credentials from the credentials file.
    ///
    /// Reads from `[default-long-term]` profile which must contain:
    /// `aws_access_key_id`, `aws_secret_access_key`, and `aws_mfa_device`.
    pub fn new(path: Option<PathBuf>, duration: u32) -> Result<Self> {
        let path = path
            .or_else(|| home_dir().map(|d| d.join(".aws/credentials")))
            .context("Could not determine home directory")?;

        ensure!(path.exists(), "Credentials file not found");

        let mut ini = Ini::new();
        ini.load(&path)
            .map_err(|e| anyhow!("Failed to load credentials: {e}"))?;

        let get = |f| ini.get("default-long-term", f).context(format!("Missing: {f}"));

        let credentials = AwsCredentials::new(
            get("aws_access_key_id")?,
            get("aws_secret_access_key")?,
            get("aws_mfa_device")?,
        );

        Ok(Self { path, credentials, duration })
    }

    /// Updates the credentials file with temporary MFA-authenticated session tokens.
    pub async fn update_credentials(&self, token: &str) -> Result<()> {
        info!("Fetching credentials - Duration: {}s", self.duration);

        let session = self.credentials.get_session_token(token, self.duration).await?;

        let content = format!(
            "[default]
aws_access_key_id={}
aws_secret_access_key={}
aws_session_token={}
aws_security_token={}
expiration={}

[default-long-term]
{}
",
            session.access_key_id(),
            session.secret_access_key(),
            session.session_token(),
            session.session_token(),
            session.expiration().fmt(Format::DateTime)?,
            self.credentials,
        );

        write(&self.path, content).await?;
        info!("Success! Credentials expire at: {}", session.expiration().fmt(Format::DateTime)?);

        Ok(())
    }
}
