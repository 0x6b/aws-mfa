//! AWS MFA Credentials Management
//!
//! This module provides functionality for managing AWS credentials and obtaining
//! temporary session tokens using Multi-Factor Authentication (MFA). It wraps
//! the AWS STS (Security Token Service) client to simplify the process of
//! authenticating with MFA devices and obtaining temporary credentials.
//!
//! # Example
//!
//! ```rust
//! use aws_mfa::credentials::AwsCredentials;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create credentials with MFA device
//! let creds = AwsCredentials::new(
//!     "AKIAIOSFODNN7EXAMPLE".to_string(),
//!     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
//!     "arn:aws:iam::123456789012:mfa/user".to_string(),
//! );
//!
//! // Get temporary session token with MFA
//! let session_token = creds.get_session_token("123456", 3600).await?;
//! # Ok(())
//! # }
//! ```

use std::{fmt, fmt::Formatter};

use anyhow::{Context, Result};
use aws_config::from_env;
use aws_sdk_sts::{Client, config::Credentials, types};

/// AWS credentials wrapper that includes MFA device information.
///
/// This struct encapsulates AWS access credentials along with the associated
/// MFA device ARN, providing a convenient way to manage credentials that
/// require multi-factor authentication for temporary session token generation.
///
/// # Fields
///
/// The struct contains the base AWS credentials (access key ID and secret access key)
/// and the MFA device identifier needed for STS operations.
///
/// # Example
///
/// ```rust
/// use aws_mfa::credentials::AwsCredentials;
///
/// let creds = AwsCredentials::new(
///     "AKIAIOSFODNN7EXAMPLE".to_string(),
///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
///     "arn:aws:iam::123456789012:mfa/user".to_string(),
/// );
/// ```
#[derive(Clone)]
pub struct AwsCredentials {
    /// The underlying AWS credentials containing access key ID and secret access key
    credentials: Credentials,
    /// The ARN of the MFA device associated with these credentials
    mfa_device: String,
}

impl AwsCredentials {
    /// Creates new AWS credentials with MFA device information.
    ///
    /// This constructor initializes an `AwsCredentials` instance with the provided
    /// access key ID, secret access key, and MFA device ARN. The credentials are
    /// configured with a provider name of "aws-mfa" for identification purposes.
    ///
    /// # Arguments
    ///
    /// * `access_key_id` - The AWS Access Key ID for authentication
    /// * `secret_access_key` - The AWS Secret Access Key for authentication
    /// * `mfa_device` - The ARN of the MFA device (e.g.,
    ///   `"arn:aws:iam::123456789012:mfa/username"`)
    ///
    /// # Returns
    ///
    /// A new `AwsCredentials` instance ready for MFA operations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use aws_mfa::credentials::AwsCredentials;
    ///
    /// let creds = AwsCredentials::new(
    ///     "AKIAIOSFODNN7EXAMPLE".to_string(),
    ///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
    ///     "arn:aws:iam::123456789012:mfa/user".to_string(),
    /// );
    /// ```
    pub fn new(access_key_id: String, secret_access_key: String, mfa_device: String) -> Self {
        Self {
            credentials: Credentials::new(access_key_id, secret_access_key, None, None, "aws-mfa"),
            mfa_device,
        }
    }

    /// Obtains temporary AWS credentials using MFA authentication.
    ///
    /// This method calls the AWS Security Token Service (STS) `GetSessionToken` API
    /// to retrieve temporary credentials that are valid for the specified duration.
    /// The MFA token from the associated device is required for authentication.
    ///
    /// # Arguments
    ///
    /// * `token` - The MFA token code (typically 6 digits) from the MFA device
    /// * `duration` - The duration in seconds for which the temporary credentials should be valid
    ///   (minimum: 900 seconds / 15 minutes, maximum: 129600 seconds / 36 hours)
    ///
    /// # Returns
    ///
    /// * `Ok(types::Credentials)` - Temporary AWS credentials containing access key ID, secret
    ///   access key, and session token
    /// * `Err(anyhow::Error)` - If the STS call fails, MFA token is invalid, or no credentials are
    ///   returned
    ///
    /// # Errors
    ///
    /// This method can fail for several reasons:
    /// - Invalid MFA token code
    /// - Expired or inactive MFA device
    /// - Network connectivity issues
    /// - AWS service errors
    /// - Invalid duration parameter (outside AWS limits)
    ///
    /// # Example
    ///
    /// ```rust
    /// use aws_mfa::credentials::AwsCredentials;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let creds = AwsCredentials::new(
    ///     "AKIAIOSFODNN7EXAMPLE".to_string(),
    ///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
    ///     "arn:aws:iam::123456789012:mfa/user".to_string(),
    /// );
    ///
    /// // Get 1-hour session token using MFA code "123456"
    /// let session_creds = creds.get_session_token("123456", 3600).await?;
    ///
    /// println!("Temporary Access Key: {}",
    ///          session_creds.access_key_id().unwrap_or("N/A"));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_session_token(
        &self,
        token: &str,
        duration: u32,
    ) -> Result<types::Credentials> {
        let config = from_env().credentials_provider(self.credentials.clone()).load().await;

        let duration_i32 = duration
            .try_into()
            .context("Duration value is too large to convert to i32")?;

        Client::new(&config)
            .get_session_token()
            .duration_seconds(duration_i32)
            .serial_number(&self.mfa_device)
            .token_code(token)
            .send()
            .await?
            .credentials()
            .cloned()
            .context("No credentials returned")
    }
}

/// Display implementation for `AwsCredentials`.
///
/// Formats the credentials in a human-readable format that shows the access key ID,
/// secret access key, and MFA device ARN. This is useful for debugging and logging
/// purposes, though care should be taken when displaying credentials in production
/// environments.
///
/// # Security Note
///
/// This implementation displays the actual secret access key, which is sensitive
/// information. In production environments, consider implementing a custom debug
/// formatter that masks or omits sensitive data.
///
/// # Format
///
/// The output format is:
/// ```text
/// aws_access_key_id=AKIAIOSFODNN7EXAMPLE
/// aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
/// aws_mfa_device=arn:aws:iam::123456789012:mfa/user
/// ```
///
/// # Example
///
/// ```rust
/// use aws_mfa::credentials::AwsCredentials;
///
/// let creds = AwsCredentials::new(
///     "AKIAIOSFODNN7EXAMPLE".to_string(),
///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
///     "arn:aws:iam::123456789012:mfa/user".to_string(),
/// );
///
/// println!("{}", creds);
/// // Output:
/// // aws_access_key_id=AKIAIOSFODNN7EXAMPLE
/// // aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
/// // aws_mfa_device=arn:aws:iam::123456789012:mfa/user
/// ```
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
