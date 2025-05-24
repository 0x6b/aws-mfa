use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use aws_smithy_types::date_time::Format;
use configparser::ini::Ini;
use log::info;
use tokio::fs;

use crate::credentials::AwsCredentials;

pub struct AwsMfaUpdater {
    path: PathBuf,
    credentials: AwsCredentials,
    duration: u32,
}

impl AwsMfaUpdater {
    pub async fn new(path: Option<PathBuf>, duration: u32) -> Result<Self> {
        let path = path
            .or_else(|| dirs::home_dir().map(|d| d.join(".aws").join("credentials")))
            .context("Could not determine home directory")?;
        ensure!(path.exists(), "Credentials file not found");

        let mut ini = Ini::new();
        ini.load(&path)
            .map_err(|e| anyhow!("Failed to load credentials: {e}"))?;

        let get = |f| ini.get("default-long-term", f).context("Missing config field: {f}");
        let credentials = AwsCredentials::new(
            get("aws_access_key_id")?,
            get("aws_secret_access_key")?,
            get("aws_mfa_device")?,
        );

        Ok(Self { path, credentials, duration })
    }

    pub async fn update_credentials(&self, token: &str) -> Result<()> {
        info!("Fetching credentials - Duration: {}s", self.duration);

        let session = self
            .credentials
            .get_session_token(token, self.duration)
            .await?;
        let access_key_id = session.access_key_id();
        let secret_access_key = session.secret_access_key();
        let session_token = session.session_token();
        let expiration = session.expiration().fmt(Format::DateTime)?;

        let content = format!(
            r#"[default]
aws_access_key_id={access_key_id}
aws_secret_access_key={secret_access_key}
aws_session_token={session_token}
aws_security_token={session_token}
expiration={expiration}

[default-long-term]
{}
"#,
            self.credentials,
        );

        fs::write(&self.path, content).await?;
        info!("Success! Credentials expire at: {expiration}");

        Ok(())
    }
}
