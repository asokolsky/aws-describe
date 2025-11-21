import json
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Any

import boto3
from botocore.exceptions import ClientError, UnauthorizedSSOTokenError

from common import eprint, json_datetime_serializer, verbose, vprint

epilog = """Examples:
    python get-tags.py -v arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0
"""


def main() -> int:
    """
    Main entry point
    """
    ap = ArgumentParser(
        description='Get AWS object tags by arn',
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
        'arn',
        help='AWS object arn',
    )
    #
    # parse the command line
    #
    args = ap.parse_args()
    global verbose
    verbose = args.verbose
    try:
        client = boto3.client('resource-explorer-2')
        resp = client.list_resources(Filters={'FilterString': f'id:{args.arn}'})
        resources = resp['Resources']
        if not resources:
            eprint('No resources found for arn:', args.arn)
            return 1
        res = resources[0]
        tags = {kv['Key']: kv['Value'] for kv in res['Properties'][0]['Data']}
        print(json.dumps(tags, indent=2, default=json_datetime_serializer))
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
