import json
import re
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Any

import boto3
import botocore.exceptions
import jmespath
from tabulate import tabulate

from .common import OutputOption, eprint, get_tag, json_datetime_serializer, parse_arn


def find_all_ids(d: dict[str, Any], verbose: bool, ignore_keys: list[str]) -> set[str]:
    """
    Iterate over d and its sub dicts, ignoring ignore_keys.

    Returns: all IDs found
    """
    res = set()
    for k, v in d.items():
        if k in ('Tags'):
            continue
        elif k in ignore_keys:
            if verbose:
                eprint(f'Ignoring {k} as requested')
            continue
        elif k == 'SecurityGroups' and isinstance(v, list):
            # print("v:", v)
            # res = res | set(v)
            for sg in v:
                if isinstance(sg, str):
                    res.add(sg)
                elif isinstance(sg, dict):
                    res = res | find_all_ids(sg, verbose, ignore_keys)
                else:
                    assert False
        elif k.endswith('Id'):
            if k in ('AvailabilityZoneId'):
                if verbose:
                    eprint(f'Ignoring {k}: {v}')
            elif '-' in v:
                res.add(v)
            else:  # noqa: PLR5501
                if verbose:
                    eprint(f'Ignoring {k}: {v}')
                # "IamInstanceProfile": {
                #    "Arn": "arn:aws:iam::123456789012:instance-profile/foo-bar",
                #    "Id": "AIPAVOS22TJGYGARJ56AT"
                # },
        elif k.endswith('Arns') and isinstance(v, list):
            res = res | set(v)
        elif k == 'InUseBy' and isinstance(v, list):
            res = res | set(v)
        elif isinstance(v, list):
            for elt in v:
                if isinstance(elt, dict):
                    res = res | find_all_ids(elt, verbose, ignore_keys)
        elif isinstance(v, dict):
            res = res | find_all_ids(v, verbose, ignore_keys)
    return res


def describe_ip_address(ip: str) -> tuple[int, dict[str, Any]]:
    """
    Do it.
    """

    client = boto3.client('ec2')
    #
    # is this a private IP associated with an eni?
    #
    res = client.describe_network_interfaces(
        Filters=[{'Name': 'addresses.private-ip-address', 'Values': [ip]}]
    )
    res = res['NetworkInterfaces']
    if res:
        return 0, res[0]
    #
    # is this a public IP associated with an eni?
    #
    res = client.describe_network_interfaces(
        Filters=[{'Name': 'association.public-ip', 'Values': [ip]}]
    )
    res = res['NetworkInterfaces']
    if res:
        return 0, res[0]
    #
    # is this an IP associated with an eni?
    #
    res = client.describe_instances(
        Filters=[{'Name': 'private-ip-address', 'Values': [ip]}]
    )
    res = res['Reservations']
    if res:
        return 0, res[0]
    #
    # is this an IP associated with an eni?
    #
    res = client.describe_instances(Filters=[{'Name': 'ip-address', 'Values': [ip]}])
    res = res['Reservations']
    if res:
        return 0, res[0]
    eprint(f'No ENIs or EIs with address {ip} found')
    return 1, {}


def describe_instance(id: str) -> tuple[int, dict[str, Any]]:
    """
    Do it.

    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_instances(InstanceIds=[id])
    res = res['Reservations']
    if res:
        return 0, res[0]['Instances'][0]
    eprint(f'No EC2 instances with id {id} found')
    return 1, {}


def describe_ami(id: str) -> tuple[int, dict[str, Any]]:
    """
    Do it.
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_images(ImageIds=[id])
    res = res['Images']
    if not res:
        eprint(f'{id} is no longer available')
        return 0, {}
    return 0, res[0]


def describe_subnet(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_subnets(SubnetIds=[id])
    return 0, res['Subnets'][0]


def describe_vpc(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_vpcs(VpcIds=[id])
    return 0, res['Vpcs'][0]


def describe_vpc_endpoint(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_vpc_endpoints(VpcEndpointIds=[id])
    return 0, res['VpcEndpoints'][0]


def describe_vpc_peering(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[id]
    )
    return 0, res['VpcPeeringConnections'][0]


def describe_vpc_cidr_assoc(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    filter = {'Name': 'cidr-block-association.association-id', 'Values': [id]}
    res = boto3.client('ec2').describe_vpcs(Filters=[filter])
    return 0, res['Vpcs'][0]


def describe_snapshot(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_snapshots(SnapshotIds=[id])
    return 0, res['Snapshots'][0]


def describe_volume(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_volumes(VolumeIds=[id])
    return 0, res['Volumes'][0]


def describe_eni(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    res = boto3.client('ec2').describe_network_interfaces(NetworkInterfaceIds=[id])
    return 0, res['NetworkInterfaces'][0]


def describe_eni_attachment(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    ec2 = boto3.client('ec2')
    filter = {'Name': 'attachment.attachment-id', 'Values': [id]}
    res = ec2.describe_network_interfaces(Filters=[filter])
    res = res['NetworkInterfaces'][0]
    return 0, res


def describe_security_group(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    ec2 = boto3.client('ec2')
    res = ec2.describe_security_groups(GroupIds=[id])
    res = res['SecurityGroups'][0]
    return 0, res


def describe_dhcp_options(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    ec2 = boto3.client('ec2')
    res = ec2.describe_dhcp_options(DhcpOptionsIds=[id])
    res = res['DhcpOptions'][0]
    return 0, res


def describe_vpn(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    ec2 = boto3.client('ec2')
    res = ec2.describe_vpn_connections(VpnConnectionIds=[id])
    res = res['VpnConnections'][0]
    return 0, res


def describe_lifecycle_policy(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    client = boto3.client('dlm')
    res = client.get_lifecycle_policy(PolicyId=id)
    res = res['Policy']
    return 0, res


def describe_certificate(arn: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    client = boto3.client('acm')
    res = client.describe_certificate(CertificateArn=arn)
    res = res['Certificate']
    return 0, res


def describe_iam_arn(res_type: str, res_name: str) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    iam = boto3.client('iam')
    if res_type == 'role':
        res = iam.get_role(RoleName=res_name)
        res = res['Role']
    elif res_type == 'instance-profile':
        res = iam.get_instance_profile(InstanceProfileName=res_name)
        res = res['InstanceProfile']
    elif res_type == 'user':
        res = iam.get_user(UserName=res_name)
        res = res['User']
    elif res_type == 'policy':
        res = iam.get_policy(PolicyArn=id)
        res = res['Policy']
    elif res_type == 'group':
        res = iam.get_group(GroupName=res_name)
        del res['IsTruncated']
        del res['ResponseMetadata']
    elif res_type == 'saml-provider':
        res = iam.get_saml_provider(SAMLProviderArn=id)
        del res['ResponseMetadata']
    else:
        eprint('ERROR: not implemented iam', res_type)
        ec = 1
    return ec, res


def describe_org_arn(res_type: str, res_name: str) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    org = boto3.client('organizations')
    if res_type == 'account':
        res = org.describe_account(AccountId=res_name)
        res = res['Account']
    elif res_type == 'ou':
        res = org.describe_organizational_unit(OrganizationalUnitId=res_name)
        res = res['OrganizationalUnit']
    # elif res_type == 'root':
    #    pass
    else:
        eprint('ERROR: not implemented organizations', res_type)
        ec = 1
    return ec, res


def describe_sm_arn(res_type: str, res_name: str) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    sm = boto3.client('secretsmanager')
    if res_type == 'secret':
        res = sm.describe_secret(SecretId=id)
        del res['ResponseMetadata']
    else:
        eprint('ERROR: not implemented secretsmanager', res_type)
        ec = 1
    return ec, res


def describe_autoscaling_arn(
    res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    client = boto3.client('autoscaling')
    if res_type == 'autoScalingGroup':
        parts = res_name.split('/')
        res = client.describe_auto_scaling_groups(AutoScalingGroupNames=[parts[-1]])
        res = res['AutoScalingGroups'][0]
    else:
        eprint('ERROR: not implemented autoscaling', res_type)
        ec = 1
    return ec, res


def describe_s3_arn(res_type: str, res_name: str) -> tuple[int, dict[str, Any]]:
    # res_name - bucket name
    # res_name - key into bucket
    if not res_name:
        eprint(f'ERROR: not implemented s3 bucket {res_type} info')
        # return describe_s3_bucket(res_type)

    bucket = res_name
    client = boto3.client('macie2')
    res = client.describe_buckets(criteria={'bucketName': {'eq': [bucket]}})
    if not res['buckets']:
        return 1, {'Error': f'Bad bucket {bucket}'}
    res = res['buckets'][0]
    return (0, res)


def describe_elbv2_arn(
    arn: str, res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    client = boto3.client('elbv2')
    if res_type == 'targetgroup':
        parts = res_name.split('/')
        name = parts[0]
        res = client.describe_target_groups(Names=[name])
        res = res['TargetGroups'][0]

    elif res_type == 'loadbalancer':
        parts = res_name.split('/')
        name = parts[1]
        res = client.describe_load_balancers(Names=[name])
        res = res['LoadBalancers'][0]
        res2 = client.describe_listeners(LoadBalancerArn=arn)
        res['listeners'] = res2['listeners']

    else:
        eprint('ERROR: not implemented for elasticloadbalancing')
        eprint(f'res_type: {res_type}')
        eprint(f'res_name: {res_name}')
        ec = 1
    return ec, res


def describe_eks_arn(
    arn: str, res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    client = boto3.client('eks')
    if res_type == 'cluster':
        res = client.describe_cluster(name=res_name)
        res = res['cluster']
    else:
        eprint('ERROR: not implemented for eks')
        eprint(f'res_type: {res_type}')
        eprint(f'res_name: {res_name}')
        ec = 1
    return ec, res


def describe_es_arn(
    arn: str, res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    client = boto3.client('es')
    if res_type == 'domain':
        res = client.describe_elasticsearch_domain(DomainName=res_name)
        res = res['DomainStatus']
    else:
        eprint('ERROR: not implemented for es')
        eprint(f'res_type: {res_type}')
        eprint(f'res_name: {res_name}')
        ec = 1
    return ec, res


def describe_ec2_arn(
    arn: str, res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    # client = boto3.client('e2')
    if res_type == 'vpc-peering-connection':
        return describe_vpc_peering(res_name)
    else:
        eprint('ERROR: not implemented for ec2')
        eprint(f'res_type: {res_type}')
        eprint(f'res_name: {res_name}')
        ec = 1
    return ec, res


def describe_acm_arn(
    arn: str, res_type: str, res_name: str
) -> tuple[int, dict[str, Any]]:
    ec = 0
    res: dict[str, Any] = {}
    # client = boto3.client('e2')
    if res_type == 'certificate':
        return describe_certificate(arn)
    else:
        eprint('ERROR: not implemented for acm')
        eprint(f'res_type: {res_type}')
        eprint(f'res_name: {res_name}')
        ec = 1
    return ec, res


def describe_arn(id: str) -> tuple[int, dict[str, Any]]:
    """
    Return exit_code, res dict.
    """
    prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(id)
    if not aws:
        # parsing arn failed
        eprint('ERROR: Failed to parse:', id)
        return 0, {}

    ec = 0
    res: dict[str, Any] = {}
    if service == 'iam':
        ec, res = describe_iam_arn(res_type, res_name)
    elif service == 'organizations':
        ec, res = describe_org_arn(res_type, res_name)
    elif service == 'secretsmanager':
        ec, res = describe_sm_arn(res_type, res_name)
    elif service == 'autoscaling':
        ec, res = describe_autoscaling_arn(res_type, res_name)
    elif service == 's3':
        ec, res = describe_s3_arn(res_type, res_name)
    elif service == 'elasticloadbalancing':
        ec, res = describe_elbv2_arn(id, res_type, res_name)
    elif service == 'eks':
        ec, res = describe_eks_arn(id, res_type, res_name)
    elif service == 'es':
        ec, res = describe_es_arn(id, res_type, res_name)
    elif service == 'ec2':
        ec, res = describe_ec2_arn(id, res_type, res_name)
    elif service == 'acm':
        ec, res = describe_acm_arn(id, res_type, res_name)
    else:
        eprint('ERROR: not implemented for', service)
        ec = 1
    return ec, res


#
# object ID patterns
#
dispatch_table = (
    (  # ec2 instance i-08f528342c7fc9873
        re.compile('^i-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an EC2 instance ID',
        describe_instance,
    ),
    (  # sg-04a142d42576c7e69
        re.compile('^sg-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a security group ID',
        describe_security_group,
    ),
    (  # ami-0889a44b331db0194
        re.compile('^ami-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an AMI ID',
        describe_ami,
    ),
    (  # eni-0c2c0fc8aadd09499
        re.compile('^eni-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an ENI ID',
        describe_eni,
    ),
    (  # vol-0a5960bcf9c0b6e97
        re.compile('^vol-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a volume ID',
        describe_volume,
    ),
    (  # vpc-82a609e6
        re.compile('^vpc-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPC ID',
        describe_vpc,
    ),
    (  # vpce-0f0ba5d8ea3c1de7b
        re.compile('^vpce-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPC endpoint ID',
        describe_vpc_endpoint,
    ),
    (  # pcx-002281f649a65b178
        re.compile('^pcx-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPC peering connection ID',
        describe_vpc_peering,
    ),
    (
        re.compile('^dopt-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a DHCP options ID',
        describe_dhcp_options,
    ),
    (  # snap-06c467df960bc252f
        re.compile('^snap-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a snapshot ID',
        describe_snapshot,
    ),
    (  # subnet-63c2f648
        re.compile('^subnet-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a subnet ID',
        describe_subnet,
    ),
    (  # policy-08c7c36bc95678ecd
        re.compile('^policy-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a lifecycle policy ID',
        describe_lifecycle_policy,
    ),
    (  # eni-attach-033c2835f89714867
        re.compile('^eni-attach-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'an ENI attachment ID',
        describe_eni_attachment,
    ),
    (  # vpc-cidr-assoc-005baf69
        re.compile('^vpc-cidr-assoc-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPC CIDR association ID',
        describe_vpc_cidr_assoc,
    ),
    (  # vpn-176b7876
        re.compile('^vpn-[a-f0-9]{8}(?:[a-f0-9]{9})?$'),
        'a VPN ID',
        describe_vpn,
    ),
    (  # arn:aws:iam::123456789012:role/foo_bar
        re.compile('^arn:aws:.*'),
        'an AWS ARN',
        describe_arn,
    ),
    (  # 192.168.10.10
        re.compile(
            r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        ),
        'an IPv4 address',
        describe_ip_address,
    ),
)

cache: dict[str, Any] = {}


def describe_one(
    id: str, verbose: bool, to_print: bool, ignore_keys: list[str], query: str
) -> tuple[int, dict[str, Any], set[str]]:
    """
    Given id locate a function which can describe it, recurse if needed.
    Side-effect, stdout, described_ids
    """

    def produce_output(res: Any, query: str) -> None:
        if query:
            res = jmespath.search(query, res)
            if not res:
                eprint(f"query '{query}' returned no result")
        print(json.dumps(res, indent=4, default=json_datetime_serializer))
        return

    if verbose:
        eprint('Describe', id)

    for p, msg, f in dispatch_table:
        if not p.search(id):
            continue
        if verbose:
            eprint(f'Treating {id} as {msg}')
        ec, res = f(id)
        if ec:
            if verbose:
                eprint(f'Error: {res}')
            return ec, res, find_all_ids(res, verbose, ignore_keys)

        if to_print:
            produce_output(res, query)
        cache[id] = res
        if verbose:
            eprint('Looking for related objects...')
        return ec, res, find_all_ids(res, verbose, ignore_keys)

    # no idea how to describe `id`
    if verbose:
        eprint(f'Failed to identify a type of instance {id}')

    return 1, {}, set()


def describe_all(
    id: str,
    verbose: bool,
    to_print: bool,
    described_ids: set[str],
    ignore_keys: list[str],
    query: str,
) -> tuple[int, set[str]]:
    """
    Implementation
    """
    ec, res, more_ids = describe_one(id, verbose, to_print, ignore_keys, query)
    described_ids.add(id)
    for id1 in more_ids - described_ids:
        ec1, res1 = describe_all(
            id1, verbose, to_print, described_ids, ignore_keys, query
        )
    return ec, described_ids


epilog = """Examples:
    python src/describe.py -r --ids subnet-f8bd4c9c
    python src/describe.py -i=AvailabilityZones,VpcId,SecurityGroups -rv arn:aws:iam::123456789012:role/foo
"""


def main() -> int:
    """
    Main entry point
    """
    ap = ArgumentParser(
        prog='aws-describe',
        description='AWS object/instance explorer',
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
        '-r',
        '--recurse',
        action='store_true',
        default=False,
        help='Describe the referenced objects',
    )
    ap.add_argument(
        '--ids',
        action='store_true',
        default=False,
        help='Only print referenced object IDs',
    )
    ap.add_argument(
        '--id-names',
        action='store_true',
        default=False,
        help='Only print referenced object ID and names',
    )
    ap.add_argument(
        '-i',
        '--ignore',
        default='',
        help='Comma-separated list of keys to ignore, relevant only when -r is used',
    )
    ap.add_argument(
        '--query', default='', help='Filter JSON output using JMESPath syntax'
    )
    ap.add_argument('instance', help='AWS object/instance ID or ARN or IPv4')
    #
    # parse the command line
    #
    args = ap.parse_args()
    if args.id_names:
        output_format = OutputOption.id_names
    elif args.ids:
        output_format = OutputOption.ids
    else:
        output_format = OutputOption.json

    ignore_keys: list[str] = args.ignore.split(',')
    try:
        to_print = output_format == OutputOption.json
        if args.recurse:
            ec, described_ids = describe_all(
                args.instance, args.verbose, to_print, set(), ignore_keys, args.query
            )
            more_ids: set[Any] = set()
        else:
            ec, res, more_ids = describe_one(
                args.instance, args.verbose, to_print, ignore_keys, args.query
            )
            described_ids = {args.instance}

        # failed to find anything matching the object ID
        if ec:
            # eprint(f'Failed to identify a type of instance {args.instance}')
            return ec

        instances = sorted(described_ids.union(more_ids))
        if output_format == OutputOption.ids:
            for id in instances:
                if id != args.instance:
                    print(id)
        elif output_format == OutputOption.id_names:
            rows: list[tuple[str, str]] = []
            for id in instances:
                # if id != args.instance:
                d = cache.get(id, {})
                name = get_tag(d, 'Name')
                # print(id, name)
                rows.append((id, name))
            print(tabulate(rows, headers=('Id', 'Name')))

        return 0

    except botocore.exceptions.ClientError as err:
        eprint('Caught: ', err)

    except KeyboardInterrupt:
        eprint('Caught KeyboardInterrupt')

    return 1


if __name__ == '__main__':
    sys.exit(main())
