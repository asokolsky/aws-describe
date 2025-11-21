import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Any

import boto3
from botocore.exceptions import ClientError, UnauthorizedSSOTokenError

from common import eprint, verbose, vprint

#
# Never take these services consideration
#
service_to_exclude: list[str] = ['athena', 'cloudfront', 'glue', 'memorydb']
#
# Never take these resource types into consideration
#
resource_type_to_exclude: list[str] = [
    #'athena:workgroup',
    'ec2:network-interface',
    'ec2:security-group-rule',
    'rds:cluster-snapshot',
]

epilog = """Examples:
    python iac-coverage.py -v
    python iac-coverage.py --region us-east-1
"""


def process_resource(resource: dict, accumulator: dict[str, dict[str, int]]) -> None:
    """
    Process a single resource and update the accumulator
    Args:
        resource: Resource dict from list_resources API
        accumulator: Dict to collect resource type statistics
    """
    rtype = resource['ResourceType']
    service = resource['Service']
    if service not in accumulator:
        accumulator[service] = {}
    service_record = accumulator[service]
    if rtype not in service_record:
        service_record[rtype] = 0
    service_record[rtype] += 1
    return


def get_object_count(
    client, query: str, accumulator: None | dict[str, dict[str, int]]
) -> int:
    """
    Get resource count using AWS Resource Explorer list_resources API.

    Args:
        client: AWS Resource Explorer client
        query: Filter query string
        accumulator: Optional dict to collect resource type statistics

    Returns:
        Total number of resources matching the query
    """
    res = client.list_resources(Filters={'FilterString': query}, MaxResults=1000)
    resources = res.get('Resources', [])
    total = len(resources)
    if accumulator is not None:
        for r in resources:
            process_resource(r, accumulator)

    while res.get('NextToken'):
        res = client.list_resources(
            Filters={'FilterString': query},
            MaxResults=1000,
            NextToken=res.get('NextToken'),
        )
        resources = res.get('Resources', [])
        total += len(resources)
        if accumulator is not None:
            for r in resources:
                process_resource(r, accumulator)
    #
    vprint(f'get_object_count({query}) -> {total}')
    return total


def full_query(query: str, region: str) -> str:
    """
    Build a full query string by adding exclusions and region if specified
    1. Exclude services in service_to_exclude
    2. Exclude resource types in resource_type_to_exclude
    3. If region is specified, add region to the query
    """
    region_query = ''
    if region:
        region_query = ' region:' + region
    service_query = ' '.join(['-service:' + s for s in service_to_exclude])
    rt_query = ' '.join(['-resourcetype:' + rt for rt in resource_type_to_exclude])
    return query + ' ' + service_query + ' ' + rt_query + region_query


def main() -> int:
    """
    Main entry point
    """
    ap = ArgumentParser(
        description='Describe IaC coverage in the context of the current AWS account',
        formatter_class=RawTextHelpFormatter,
        epilog=epilog,
    )
    ap.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=False,
        help='make some helpful noises',
    )
    ap.add_argument(
        '--region',
        default='',
        help='narrow the scope to this AWS region, defaults to the default region AND global objects',
    )
    #
    # parse the command line
    #
    args = ap.parse_args()
    global verbose
    verbose = args.verbose
    try:
        client = boto3.client('resource-explorer-2')

        query = 'tag.key:clari:managed-by'
        total = get_object_count(client, full_query(query, args.region), None)
        print('Tagged:', total)
        #
        # by Service / ResourceType / Count
        #
        acc: None | dict[str, dict[str, int]] = {} if verbose else None
        query = 'tag:none -tag.key:aws*'
        total = get_object_count(client, full_query(query, args.region), acc)
        print('Untagged:', total)
        if acc:
            for service in acc:
                print(f'Service: {service}: {sum(acc[service].values())}')
                for rtype in acc[service]:
                    print(f'  {rtype}: {acc[service][rtype]}')
        return 0

    except ClientError as err:
        eprint('Caught: ', err)

    except UnauthorizedSSOTokenError as err:
        eprint('Caught: ', err)

    except KeyboardInterrupt:
        eprint('Caught KeyboardInterrupt')

    return 1


if __name__ == '__main__':
    sys.exit(main())
