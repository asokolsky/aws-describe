import json
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Any

import boto3
from botocore.exceptions import ClientError, UnauthorizedSSOTokenError

from common import eprint, json_datetime_serializer, verbose, vprint

epilog = """Examples:
    python get-secret.py -v foo-bar-baz
"""


def main() -> int:
    """
    Main entry point
    """
    ap = ArgumentParser(
        description='Get AWS secret by name',
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
    ap.add_argument('secret_name', help='AWS secret name')
    #
    # parse the command line
    #
    args = ap.parse_args()
    global verbose
    verbose = args.verbose
    try:
        client = boto3.client('secretsmanager')
        resp = client.get_secret_value(SecretId=args.secret_name)
        if 'SecretString' in resp:
            secret = json.loads(resp['SecretString'])
            print(json.dumps(secret, indent=2, default=json_datetime_serializer))
            return 0

        eprint(resp)
        return 1

    except ClientError as err:
        eprint('Caught: ', err)

    except UnauthorizedSSOTokenError as err:
        eprint('Caught: ', err)

    except KeyboardInterrupt:
        eprint('Caught KeyboardInterrupt')

    return 1


if __name__ == '__main__':
    sys.exit(main())
