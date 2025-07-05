import json
import re
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Any

import boto3
import botocore.exceptions

# local import
from .common import OutputOption, get_tag, json_datetime_serializer, parse_arn

#
# object ID patterns
#
filter_table = (
    (  # i-08f528342c7fc9873
        re.compile('^i-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an EC2 instance ID',
        'instance-id',
    ),
    (  # sg-04a142d42576c7e69
        re.compile('^sg-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a security group ID',
        'instance.group-id',
    ),
    (  # ami-0889a44b331db0194
        re.compile('^ami-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an AMI ID',
        'image-id',
    ),
    (  # eni-0c2c0fc8aadd09499
        re.compile('^eni-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an ENI ID',
        'network-interface.network-interface-id',
    ),
    (  # eni-attach-033c2835f89714867
        re.compile('^eni-attach-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an ENI attachment ID',
        'network-interface.attachment.attachment-id',
    ),
    (  # vol-0a5960bcf9c0b6e97
        re.compile('^vol-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a volume ID',
        'block-device-mapping.volume-id',
    ),
    (  # vpc-82a609e6
        re.compile('^vpc-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPC ID',
        'network-interface.vpc-id',
    ),
    (  # subnet-63c2f648
        re.compile('^subnet-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a subnet ID',
        'network-interface.subnet-id',
    ),
    (
        re.compile('^arn:aws:iam::[0-9]{12}:instance-profile/.*'),
        'an instance profile arn',
        'iam-instance-profile.arn',
    ),
    (  # 10.0.0.1
        re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
        'a private IPV4 address',
        'network-interface.addresses.private-ip-address',
    ),
)


def find_instances_by_asg(
    service: str, region: str, acct_id: str, res_type: str, res_name: str
) -> list[dict[str, Any]]:
    """
    Find instances_by an ASG.
    """
    instances: list[dict[str, Any]] = []
    if service == 'autoscaling' and res_type == 'autoScalingGroup':
        client = boto3.client('autoscaling')
        parts = res_name.split('/')
        res = client.describe_auto_scaling_groups(AutoScalingGroupNames=[parts[-1]])
        res = res['AutoScalingGroups'][0]['Instances']
        ids = [r['InstanceId'] for r in res]
        ec2 = boto3.client('ec2')
        res = ec2.describe_instances(InstanceIds=ids)
        for reservation in res['Reservations']:
            instances.extend(reservation['Instances'])

    return instances


#
# object ID patterns
#
dispatch_table = (
    (
        re.compile('^arn:aws:autoscaling:.+:[0-9]{12}:autoScalingGroup:.+'),
        'an autoScalingGroup arn',
        find_instances_by_asg,
    ),
)


def find_instances_by_filter(
    id: str, filters: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Call ec2.describe_instances with a filter.
    """
    ec2 = boto3.client('ec2')
    instances: list[dict[str, Any]] = []
    nextToken = ''
    while True:
        res = ec2.describe_instances(
            Filters=filters, MaxResults=100, NextToken=nextToken
        )
        for reservation in res['Reservations']:
            instances.extend(reservation['Instances'])
        nextToken = res.get('NextToken', '')
        if not nextToken:
            break
    return instances


def find_instances(
    id: str, verbose: bool, format: OutputOption
) -> tuple[int, list[str]]:
    """
    Given the id, locate a filter, then apply it.
    Side-effect, stdout
    Returns exit code, list of instance IDs
    """

    filters: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []

    # populate the above filters based on the ID type
    for p, msg, f in filter_table:
        if p.search(id):
            if verbose:
                print(f'Treating {id} as {msg}', file=sys.stderr)
            filters.append({'Name': f, 'Values': [id]})

    if filters:
        instances = find_instances_by_filter(id, filters)

    else:
        # try dispatch table
        for p, msg, foo in dispatch_table:
            if p.search(id):
                if verbose:
                    print(f'Treating {id} as {msg}', file=sys.stderr)
                prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(
                    id
                )
                instances = foo(service, region, acct_id, res_type, res_name)

    # failed to find anything matching the object ID
    if not instances:
        if verbose:
            print(f"Treating '{id}' as the instance name", file=sys.stderr)
        filters = [{'Name': 'tag:Name', 'Values': [id]}]
        instances = find_instances_by_filter(id, filters)

    if verbose:
        # https://stackoverflow.com/questions/21872366/plural-string-formatting
        total = len(instances)
        print(f'Found {total} instance{"s"[: total ^ 1]}:', file=sys.stderr)

    if format == OutputOption.ids:
        for i in instances:
            print(i['InstanceId'])
    elif format == OutputOption.id_names:
        for i in instances:
            print(i['InstanceId'], get_tag(i, 'Name'))
    else:
        print(json.dumps(instances, indent=4, default=json_datetime_serializer))

    return 0, [i['InstanceId'] for i in instances]


def terminate_instances(ids: list[str], verbose: bool) -> int:
    """
    Terminate the ec2 instances enumerated in ids.
    Returns the exit code
    """
    if not ids:
        if verbose:
            print('No instances to terminate', file=sys.stderr)
        return 0

    ec2 = boto3.client('ec2')
    res = ec2.terminate_instances(InstanceIds=ids, DryRun=True)
    res = res.get('TerminatingInstances', [])
    if not res:
        if verbose:
            print('Failed to terminate', ids, file=sys.stderr)
        return 1
    if verbose:
        for i in res:
            print(
                f"{i['InstanceId']}: from '{i['PreviousState']['Name']}' to '{i['CurrentState']['Name']}'"
            )
    return 0


epilog = """Examples:
    python src/find-instance.py 10.6.64.23
    python src/find-instance.py --id-names sg-73953806
    python src/find-instance.py -v --ids vpc-82a609e6
    python src/find-instance.py arn:aws:iam::123456789012:instance-profile/grimer_production
"""


def main() -> int:
    """Main entry point."""

    ap = ArgumentParser(
        prog='aws-find-instance',
        description='Find an AWS EC2 instance(s) by a related ID or ARN',
        formatter_class=RawTextHelpFormatter,
        epilog=epilog,
    )
    ap.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=False,
        help='Tell more about what is going on',
    )
    ap.add_argument(
        '--ids', action='store_true', default=False, help='Print instance IDs only'
    )
    ap.add_argument(
        '--id-names',
        action='store_true',
        default=False,
        help='Print instance ID and names only',
    )
    ap.add_argument(
        '--terminate',
        action='store_true',
        default=False,
        help='Terminate the instance(s)',
    )
    ap.add_argument('instance', help='AWS object/instance ID or ARN')
    #
    # parse the command line
    #
    args = ap.parse_args()
    if args.id_names:
        format = OutputOption.id_names
    elif args.ids:
        format = OutputOption.ids
    else:
        format = OutputOption.json

    try:
        ec, ids = find_instances(args.instance, args.verbose, format)
        if (ec == 0) and args.terminate:
            ec = terminate_instances(ids, args.verbose)
        return ec

    except botocore.exceptions.ClientError as err:
        print('Caught: ', err, file=sys.stderr)

    return 1


if __name__ == '__main__':
    sys.exit(main())
