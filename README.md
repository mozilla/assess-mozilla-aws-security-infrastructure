# assess-mozilla-aws-security-infrastructure

This tool scans Mozilla AWS accounts checking for security infrastructure. It
reports accounts which are missing elements of that infrastructure.

This includes any accounts either missing or with misconfigured

* GuardDuty IAM Roles that the GuardDuty Multi Account Master uses to accept invitations
* GuardDuty relationships between member and parent
* CloudTrail
* Security Audit IAM Roles and Incident Response IAM Roles
* Mozilla Single Sign On (SSO)

## Usage

Run `assess-mozilla-aws-security-infrastructure`

## Future Work

Currently, the tool just prints out information. This could be improved or turned
into machine-readable structured data

The tool does not assess whether there are any IAM users with passwords defined
in an account that has SSO enabled (these IAM users should be removed in favor
of SSO)

