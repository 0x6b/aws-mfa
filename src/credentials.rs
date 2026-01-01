//! AWS credentials management with MFA support.

use std::fmt::{self, Formatter};

use anyhow::{Context, Result};
use aws_config::from_env;
use aws_sdk_sts::{Client, config::Credentials, types};

/// AWS credentials with MFA device information.
#[derive(Clone)]
pub struct AwsCredentials {
    credentials: Credentials,
    mfa_device: String,
}

impl AwsCredentials {
    /// Creates new AWS credentials with MFA device ARN.
    pub fn new(access_key_id: String, secret_access_key: String, mfa_device: String) -> Self {
        Self {
            credentials: Credentials::new(access_key_id, secret_access_key, None, None, "aws-mfa"),
            mfa_device,
        }
    }

    /// Obtains temporary credentials using MFA authentication via STS GetSessionToken.
    pub async fn get_session_token(
        &self,
        token: &str,
        duration: u32,
    ) -> Result<types::Credentials> {
        let config = from_env().credentials_provider(self.credentials.clone()).load().await;

        Client::new(&config)
            .get_session_token()
            .duration_seconds(i32::try_from(duration).context("Duration too large")?)
            .serial_number(&self.mfa_device)
            .token_code(token)
            .send()
            .await?
            .credentials()
            .cloned()
            .context("No credentials returned")
    }
}

impl fmt::Display for AwsCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "aws_access_key_id={}\naws_secret_access_key={}\naws_mfa_device={}",
            self.credentials.access_key_id(),
            self.credentials.secret_access_key(),
            self.mfa_device
        )
    }
}
