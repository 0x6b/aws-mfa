# `aws-mfa`

A Rust CLI tool for refreshing AWS session credentials using Multi-Factor Authentication (MFA). This tool implements a dual-profile strategy to preserve your long-term credentials while providing temporary session tokens for AWS operations.

> [!CAUTION]
> This tool is designed for my specific use case and may not work with your setup. It will delete your `~/.aws/credentials` without prior confirmation. Use it at your own risk, or consider using other tools like [jhandguy/aws-mfa](https://github.com/jhandguy/aws-mfa) and [eegli/mfaws](https://github.com/eegli/mfaws).

## Features

- **Dual-Profile Architecture**: Preserves long-term credentials in `[default-long-term]` while writing temporary session tokens to `[default]`
- **1Password Integration**: Automatic MFA token retrieval from 1Password CLI with manual fallback
- **Configurable Session Duration**: Support for AWS STS session durations (15 minutes to 36 hours)
- **Smart Region Detection**: Automatically detects AWS region from environment, config file, or EC2 metadata
- **Graceful Error Handling**: Continues operation even if 1Password CLI fails, falling back to manual token entry
- **AWS SDK Compatibility**: Generates credentials compatible with all AWS SDKs and tools

## Usage

```bash
aws-mfa [OPTIONS]

Options:
  -c, --credentials-path <CREDENTIALS_PATH> Path to AWS credentials file [env: AWS_SHARED_CREDENTIALS_FILE]
  -d, --duration <DURATION>                 Session duration in seconds [env: AWS_SESSION_DURATION] [default: 43200]
      --op-account <OP_ACCOUNT>             1Password account (e.g., yourcompany.1password.com) [env: AWS_MFA_UPDATER_OP_ACCOUNT]
      --op-item-name <OP_ITEM_NAME>         1Password item name containing MFA token [env: AWS_MFA_UPDATER_OP_ITEM_NAME]
  -h, --help                                Print help
  -V, --version                             Print version
```

### Environment Variables

You can configure the tool using environment variables:

| Variable                       | Description                              | Default              |
| ------------------------------ | ---------------------------------------- | -------------------- |
| `AWS_SHARED_CREDENTIALS_FILE`  | Path to AWS credentials file             | `~/.aws/credentials` |
| `AWS_SESSION_DURATION`         | Session duration in seconds              | `43200`              |
| `AWS_MFA_UPDATER_OP_ACCOUNT`   | 1Password account URL                    | -                    |
| `AWS_MFA_UPDATER_OP_ITEM_NAME` | 1Password item name containing MFA token | -                    |

The AWS region is automatically detected from:

- Environment variables (`AWS_DEFAULT_REGION`, `AWS_REGION`)
- AWS config file (`~/.aws/config`)
- EC2 instance metadata (when running on AWS)

## How It Works

The tool uses a **dual-profile strategy** to manage AWS credentials safely:

1. **Long-term credentials** are stored in the `[default-long-term]` profile (never modified)
2. **Temporary session tokens** are written to the `[default]` profile (used by AWS tools)
3. **MFA authentication** exchanges your MFA token for temporary credentials via AWS STS
4. **Session tokens** include both access credentials and session tokens for full AWS SDK compatibility

This approach ensures your permanent credentials are never lost or overwritten.

## Prerequisites

### AWS Configuration

Ensure you have your AWS credentials configured in `~/.aws/credentials` with long-term credentials:

```ini
[default-long-term]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
aws_mfa_device = arn:aws:iam::ACCOUNT:mfa/USERNAME
```

### 1Password Integration (Optional)

For automatic MFA token retrieval, ensure:

1. **1Password CLI** is installed and authenticated (`op signin`)
2. **MFA item** exists in 1Password with TOTP configured
3. **Account and item name** are provided via CLI flags or environment variables

If 1Password integration fails, the tool gracefully falls back to manual token entry.

## Examples

### Basic Usage

```bash
# Use manual MFA token entry
aws-mfa

# With 1Password integration
aws-mfa --op-account yourcompany.1password.com --op-item-name "AWS MFA"

# Custom duration (8 hours)
aws-mfa --duration 28800

# Custom credentials file
aws-mfa --credentials-path ~/.aws/work-credentials
```

### With Environment Variables

```bash
export AWS_MFA_UPDATER_OP_ACCOUNT="yourcompany.1password.com"
export AWS_MFA_UPDATER_OP_ITEM_NAME="AWS MFA"
export AWS_SESSION_DURATION="14400"  # 4 hours

aws-mfa  # Uses environment variables
```

### Generated Credentials File

After running the tool, your `~/.aws/credentials` will contain:

```ini
[default-long-term]
aws_access_key_id = AKIA...
aws_secret_access_key = abc123...
aws_mfa_device = arn:aws:iam::123456789012:mfa/username

[default]
aws_access_key_id = ASIA...
aws_secret_access_key = xyz789...
aws_session_token = IQoJb3JpZ2luX2VjE...
aws_security_token = IQoJb3JpZ2luX2VjE...
```

The `[default]` profile contains temporary credentials that AWS tools will use automatically.

## License

MIT

## Acknowledgements

- [broamski/aws-mfa: Manage AWS MFA Security Credentials](https://github.com/broamski/aws-mfa) for the original idea and inspiration.
