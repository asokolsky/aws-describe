import sys
from datetime import date, datetime
from enum import Enum
from typing import Any, Union


class OutputOption(str, Enum):
    """
    CLI program output options.
    """

    json = 'json'
    ids = 'ids'
    id_names = 'id-names'

    @classmethod
    def is_valid(cls, st: Union[str, 'OutputOption']) -> bool:
        return st in cls._value2member_map_

    def __repr__(self) -> str:
        """To enable serialization as a string..."""
        return repr(self.value)


def get_tag(d: dict[str, Any], tag_key: str) -> Any:
    """
    Retrieve just one tag.

    Returns None if the tag not present
    """
    for tag in d.get('Tags', []):
        if tag.get('Key', '') == tag_key:
            return tag.get('Value', None)

    return None


def json_datetime_serializer(obj: Any) -> str:
    """
    Serialize datetime fields.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f'Type {type(obj)} not serializable')


def parse_arn(arn: str) -> tuple[str, str, str, str, str, str, str]:
    """
    Parse the arn.

    Returns (
        'arn',
        'aws', partition
        'iam', service
        '',    region
        '374926383693',  accountID
        'role', - resource_type (can be '')
        'grimer_staging' - resource_name
    )
    """
    prefix = aws = service = region = acct_id = res_type = res_name = ''
    parts = arn.split(':')
    if len(parts) < 6:
        # bad format
        pass
    else:
        prefix = parts[0]
        aws = parts[1]
        service = parts[2]
        region = parts[3]
        acct_id = parts[4]
        if len(parts) == 6:
            res_name = parts[5]
            if '/' in parts[5]:
                res_parts = parts[5].split('/')
                res_type = res_parts[0]
                res_name = '/'.join(res_parts[1:])
        else:  # len(parts) >= 7:
            res_type = parts[5]
            res_name = ':'.join(parts[6:])
    # if not prefix:
    #    print('ERROR: Failed to parse:', arn, file=sys.stderr)
    return (prefix, aws, service, region, acct_id, res_type, res_name)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


verbose = False


def vprint(*args: Any) -> None:
    if verbose:
        print(*args)
