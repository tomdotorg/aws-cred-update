# Perform multi-factor authentication to aws and write the resulting token to a credentials file

## Assumptions

My aws credentials file looks like the one below. One of the parameters to this utility is the section name containing the access key and secret keys used to obtin a token. The default is `setup` as you see below. Also, note how the role I want to assume by default is in the `default` section and is associate with the `sts` section. This utility will create the `sts` section or if it already exists, it will overwrite the existing one!

Sample ~/.aws/credentials file:

```windows
[setup]
aws_access_key_id     = AKIA5SHSUS&&SSSDFVGT
aws_secret_access_key = Y1QJh+OvhnVrGk5hLinLx9bPDe7MlTweFdTD+oec

[default]
role_arn       = arn:aws:iam::636934561231:role/SomeRoleYouWant
source_profile = sts

[sts]
aws_secret_access_key = 2TmBwKPq54cWOAZTrHqxAa697Jf0hhstRSFGHS653
aws_access_key_id     = ASIA5VJSDYSSHY6645789GG
aws_session_token     = HHSGT5542ldzEEAaDJoOMnIX+NLNctzxRCKGAWVTt/zEbt/3jiXq4h3YsQDsQ4uPoM1pu0IbDJI7hFvEKJRVbgKB22aMliTPE14/EwEArY7rHrJFXDnSY7gFo//W0/6dwWKgHBzoj+aSXGF8MBnE+HeKlcC+ZTqBtZElIvEnwkDarkgLRq8bhEv4kJQhLGqVh1CFjY9SkjljxQBXolrAXpvIKJPM6/IFMii/FJ6C9215uwmmttgd4uligBmzlYBnElwslQ3VuKgFdFJHJJSYSKI9
```

## Installation

`go get github.com/tomdotorg/aws-cred-update` will leave the `aws-cred-update` binary in the ./bin directory.

## Usage

`aws-cred-update -s <serialNum> -t <mfaToken> [ -p <profileName> -l <debug|info|warn|error> -i <inputFile> -o <outputfile> ]`
  
- -s - aws arn of the principal being authenticated. For example `arn:aws:iam::9876523449813:mfa/myman@example.com`
- -t - mfa token obtained by a device, text, or whatever for example `123456` from Google Authenticator
- -p - profile name in the credentials file containing the access key id and secret key used to obtain a token. default is `setup`
- -l - log level which must be one of `debug`, `info`, `warn`, `error`. `info` is the default
- -i - the full path to the credentials file used as input. default is `~/.aws/credentials`
- -o - the full path to the output credentials file. default is `~/.aws/credentials` ***note: if the input and output are the same. overwrite the output***

If you tun the logging level to warn with `-l warn`, you can capture the exports of the environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

More informatio on how this works at the [AWS website](https://aws.amazon.com/premiumsupport/knowledge-center/authenticate-mfa-cli/).
