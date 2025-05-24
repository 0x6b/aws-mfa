# `aws-mfa`

A Rust CLI tool for refreshing AWS session credentials using Multi-Factor Authentication (MFA).

## Features

- Refresh AWS session credentials using MFA
- Support for 1Password integration for MFA token retrieval
- Configurable session duration

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
|--------------------------------|------------------------------------------|----------------------|
| `AWS_SHARED_CREDENTIALS_FILE`  | Path to AWS credentials file             | `~/.aws/credentials` |
| `AWS_SESSION_DURATION`         | Session duration in seconds              | `43200`              |
| `AWS_MFA_UPDATER_OP_ACCOUNT`   | 1Password account URL                    | -                    |
| `AWS_MFA_UPDATER_OP_ITEM_NAME` | 1Password item name containing MFA token | -                    |

The AWS region is automatically detected from:
- Environment variables (`AWS_DEFAULT_REGION`, `AWS_REGION`)
- AWS config file (`~/.aws/config`)
- EC2 instance metadata (when running on AWS)

## Prerequisites

### AWS Configuration

Ensure you have your AWS credentials configured in `~/.aws/credentials` with long-term credentials:

```ini
[default-long-term]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
aws_mfa_device = arn:aws:iam::ACCOUNT:mfa/USERNAME
```

## License

MIT

## Acknowledgements

- [broamski/aws-mfa: Manage AWS MFA Security Credentials](https://github.com/broamski/aws-mfa) for the original idea and inspiration.
