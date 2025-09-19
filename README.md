# aws-describe

CLI utilities to:

* (recursively) describe AWS resources by ID or ARN.
* find an EC2 instance by ID or ARN of the related resource.

## Usage

To run tests:
```
> make test
```

## Describe Object

Login into your AWS account.  As a side-effect this usually sets environment
variables `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and,
sometimes,  `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`.

Then:
```
> uv run src/describe.py -h
usage: aws-describe [-h] [-r] [--ids] [--id-names] [-v] instance

AWS object/instance explorer

positional arguments:
  instance       AWS object/instance ID or ARN or IPv4

options:
  -h, --help     show this help message and exit
  -v, --verbose  Tell more about what is going on
  -r, --recurse  Describe the referenced objects
  --ids          Only print referenced object IDs
  --id-names     Only print referenced object ID and names

Examples:
    python src/describe.py -r --ids subnet-f8bd4c9c
    python src/describe.py -v arn:aws:iam::123456789012:role/foo
```

Another example, now using `--query` with [JMESPath](https://jmespath.org/)
syntax:
```
uv run src/describe.py vpn-176b7876  --query CustomerGatewayConfiguration
```
is equivalent to:
```sh
aws ec2 describe-vpn-connections \
  --filter 'Name=vpn-connection-id,Values=vpn-176b7876' \
  --query 'VpnConnections[0].CustomerGatewayConfiguration' \
  --output text
```

## Find Instance

Login into your AWS account.  As a side-effect this usually sets environment
variables `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and,
sometimes,  `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`.

Then:
```
> uv run src/find-instance.py -h
usage: aws-find-instance [-h] [-v] [--ids] [--id-names] [--terminate] instance

Find an AWS EC2 instance(s) by a related ID or ARN

positional arguments:
  instance       AWS object/instance ID or ARN

options:
  -h, --help     show this help message and exit
  -v, --verbose  Tell more about what is going on
  --ids          Print instance IDs only
  --id-names     Print instance ID and names only
  --terminate    Terminate the instance(s)

Examples:
    python src/find-instance.py 10.6.64.23
    python src/find-instance.py --id-names sg-73953806
    python src/find-instance.py -v --ids vpc-82a609e6
    python src/find-instance.py arn:aws:iam::123456789012:instance-profile/foo_bar
```

TODO: use mise
