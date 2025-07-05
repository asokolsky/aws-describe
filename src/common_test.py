import unittest

from .common import parse_arn


class ParseArnTest(unittest.TestCase):
    def test_parse_arn(self) -> None:
        arn = 'arn:aws:iam::123456789012:instance-profile/foobar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'iam')
        self.assertEqual(region, '')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, 'instance-profile')
        self.assertEqual(res_name, 'foobar')

        arn = 'arn:aws:iam::123456789012:instance-profile/foo/bar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'iam')
        self.assertEqual(region, '')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, 'instance-profile')
        self.assertEqual(res_name, 'foo/bar')

        arn = 'arn:aws:iam::123456789012:instance-profile:foobar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'iam')
        self.assertEqual(region, '')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, 'instance-profile')
        self.assertEqual(res_name, 'foobar')

        arn = 'arn:aws:iam::123456789012:foobar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'iam')
        self.assertEqual(region, '')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, '')
        self.assertEqual(res_name, 'foobar')

        arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:staging/foobar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'secretsmanager')
        self.assertEqual(region, 'us-east-1')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, 'secret')
        self.assertEqual(res_name, 'staging/foobar')

        arn = 'arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:f1765771-8b20-424c-83e4-7a960ce3b479:autoScalingGroupName/foo-bar-production-asg'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 'autoscaling')
        self.assertEqual(region, 'us-east-1')
        self.assertEqual(acct_id, '123456789012')
        self.assertEqual(res_type, 'autoScalingGroup')
        self.assertEqual(
            res_name,
            'f1765771-8b20-424c-83e4-7a960ce3b479:autoScalingGroupName/foo-bar-production-asg',
        )

        # arn:aws:iam::123456789012:user/okta-sso-user
        # arn:aws:organizations::123456789012:root/o-rhaczyc90z/r-h68e
        # arn:aws:organizations::123456789012:ou/o-rhaczyc90z/ou-h68e-zirf3o0o
        # arn:aws:organizations::123456789012:account/o-rhaczyc90z/063495072266

        arn = 'arn:aws:s3:::foo-bar'
        prefix, aws, service, region, acct_id, res_type, res_name = parse_arn(arn)
        self.assertEqual(prefix, 'arn')
        self.assertEqual(aws, 'aws')
        self.assertEqual(service, 's3')
        self.assertEqual(region, '')
        self.assertEqual(acct_id, '')
        self.assertEqual(res_type, '')
        self.assertEqual(res_name, 'foo-bar')

        return
