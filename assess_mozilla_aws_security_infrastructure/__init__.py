import os
import json
import boto3
from boto3.dynamodb.conditions import Key
from typing import List, Set, Tuple
from datetime import datetime, timedelta, timezone
from persistent_cache import cache

CLOUDTRAIL_BUCKET = 'mozilla-cloudtrail-logs'
CLOUDTRAIL_SNS_TOPIC_ARN = "arn:aws:sns:us-west-2:088944123687:MozillaCloudTrailLogs"
CLOUDTRAIL_READER_ROLE = 'arn:aws:iam::088944123687:role/Infosec-Prod-CloudTrail-Log-Reader'
GROUP_ROLE_MAP_S3_BUCKET = 'mozilla-infosec-auth0-rule-assets'
GROUP_ROLE_MAP_FILENAME = 'access-group-iam-role-map.json'
TABLE_NAME = os.getenv('TABLE_NAME', 'cloudformation-stack-emissions')
TABLE_REGION = os.getenv('TABLE_REGION', 'us-west-2')
TABLE_INDEX_NAME = os.getenv('TABLE_INDEX_NAME', 'category')
TABLE_PRIMARY_PARTITION_KEY_NAME = 'aws-account-id'
TABLE_PRIMARY_SORT_KEY_NAME = 'id'
SECURITY_AUDIT_ROLE_TABLE_CATEGORY = 'AWS Security Auditing Service'
SECURITY_AUDIT_ROLE_TABLE_ATTRIBUTE = 'SecurityAuditIAMRoleArn'
GUARDDUTY_ROLE_TABLE_CATEGORY = 'GuardDuty Multi Account Member Role'
GUARDDUTY_ROLE_TABLE_ATTRIBUTE = 'GuardDutyMemberAccountIAMRoleArn'


# https://mana.mozilla.org/wiki/display/SECURITY/AWS+Cross+Organization+Access
ORGANIZATION_READER_ROLES = {
    'IT': 'arn:aws:iam::329567179436:role/Organization-Reader',
    'Pocket': 'arn:aws:iam::996905175585:role/Organization-Reader',
    'Mozilla Foundation': 'arn:aws:iam::943761894018:role/Organization-Reader',
    'Firefox Services': 'arn:aws:iam::361527076523:role/Infosec-Organization-Reader'
}
TEN_MINUTES_FROM_NOW = datetime.now(timezone.utc) + timedelta(minutes=10)


@cache(lambda x: x.get('expiration', datetime.now(timezone.utc)) < TEN_MINUTES_FROM_NOW)
def get_credentials(iam_role_arn, session_name=None, policy=None) -> dict:
    """Given an AWS IAM Role, return a dict of credentials

    Note : Since policy is a dict, the cache memoization works when the policy
    is the same because in Python 3.6 and later, dicts are order-preserving

    :param iam_role_arn: AWS IAM Role ARN
    :param session_name: User definable name to label the session with
    :param policy: IAM policy to constrain the permissions available from the
        role
    :return: dict of credentials
    """

    args = {'RoleArn': iam_role_arn,
            'RoleSessionName': session_name if session_name else iam_role_arn}
    if policy:
        args['Policy'] = policy
    client = boto3.client('sts')
    response = client.assume_role(**args)
    credentials = {
        'aws_access_key_id': response['Credentials']['AccessKeyId'],
        'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
        'aws_session_token': response['Credentials']['SessionToken'],
        'expiration': response['Credentials']['Expiration']
    }
    return credentials


def get_paginated_results(
        product, action, key, credentials=None, args=None) -> List:
    """Get paginated results from an AWS API call

    :param product: The AWS product to call
    :param action: The action to call within that product
    :param key: The dict key that results should be within
    :param credentials: The credential dict to use when making the call
    :param args: The arguments to pass to the action
    :return: A list of results
    """
    args = {} if args is None else args
    credentials = {} if credentials is None else credentials
    return [y for sublist in [x[key] for x in boto3.client(
        product, **credentials).get_paginator(action).paginate(**args)]
            for y in sublist]


def get_role_arns(table_category, table_attribute_name) -> List[str]:
    """Fetch all AWS IAM Role ARNs stored in DynamoDB for a given attribute

    This is for querying the CloudFormation Cross Account Outputs table
    https://github.com/mozilla/cloudformation-cross-account-outputs

    :param table_category: The category of outputs stored in the table
    :param table_attribute_name: The attribute to fetch
    :return: A list of AWS IAM Role ARNs
    """
    dynamodb = boto3.resource('dynamodb', region_name=TABLE_REGION)
    table = dynamodb.Table(TABLE_NAME)
    items = table.query(
        IndexName=TABLE_INDEX_NAME,
        Select='SPECIFIC_ATTRIBUTES',
        ProjectionExpression=table_attribute_name,
        KeyConditionExpression=Key(TABLE_INDEX_NAME).eq(table_category)
    )['Items']
    return [x[table_attribute_name] for x in items
            if table_attribute_name in x]


def get_sso_accounts() -> Set[str]:
    """Extract set of all AWS account IDs for SSO enabled accounts

    This fetches the Mozilla AWS SSO group role map and extracts the set of
    AWS accounts which have IAM roles that use SSO.

    :return: A set of AWS account IDs
    """
    client = boto3.client('s3')
    response = client.get_object(
        Bucket=GROUP_ROLE_MAP_S3_BUCKET,
        Key=GROUP_ROLE_MAP_FILENAME,
    )
    data = json.load(response['Body'])
    roles = []
    account_ids = []
    for group in data:
        roles.extend(data[group])
    for role in set(roles):
        account_ids.append(role.split(':')[4])
    return set(account_ids)


def get_org_accounts():
    """Connect to each AWS Organization parent and collect the account IDs

    This assumes role into each AWS Organization parent, lists account IDS
    and combines them together into a dict with the ID as the key and the name
    of the AWS Organization as the value

    :return: dict of AWS account IDs and AWS Organization names
    """
    all_accounts = {}
    for organization_name, organization_reader_role in ORGANIZATION_READER_ROLES.items():
        credentials = get_credentials(
            organization_reader_role,
            'CheckForMissingRoles-OrgReader',
            '{"Version":"2012-10-17","Statement":[{"Sid":"ListOrgAccounts","Effect":"Allow","Action":"organizations:ListAccounts","Resource":"*"}]}'
        )
        del (credentials['expiration'])
        account_list = get_paginated_results(
            'organizations', 'list_accounts', 'Accounts', credentials)
        active_account_list = [x for x in account_list
                               if x['Status'] == 'ACTIVE']
        all_accounts.update(
            {x['Id']: dict(x, Organization=organization_name)
             for x in active_account_list})
    return all_accounts


def cache_security_audit_credentials(arn_list, session_name, policy):
    """Iterate over a list of IAM Roles, assuming each and return any failures

    This serves to pre-cache credentials for all the IAM roles needed. Any
    failures that are encountered are collected in a dict with the key being
    the AWS IAM Role ARN and the value being the error message

    :param arn_list: list of AWS IAM Role ARNs
    :param session_name: User definable name to label the session with
    :param policy: IAM policy to constrain the permissions available from the
        role
    :return: dict of IAM Role assumption failures. IAM Role ARN as the key and
        error message as the value
    """
    failures = {}
    for role_arn in arn_list:
        try:
            get_credentials(role_arn, session_name, policy)
        except Exception as e:
            failures[role_arn] = str(e)
    return failures


def is_cloudtrail_valid(trail):
    """Test a CloudTrail trail for any misconfigurations

    :param trail: A CloudTrail trail dict containing information about the
        trail
    :return: True if the trail is correctly configured. False if the trail
        writes to a non-standard S3 bucket
    """
    storage_account = trail['TrailARN'].split(':')[4]
    kms_account = (
        trail['KmsKeyId'].split(':')[4] if 'KmsKeyId' in trail else None)
    if trail['S3BucketName'] != CLOUDTRAIL_BUCKET:
        return False
    elif trail['SnsTopicARN'] != CLOUDTRAIL_SNS_TOPIC_ARN:
        raise Exception(
            f"CloudTrail sends to {CLOUDTRAIL_BUCKET} but it is misconfigured "
            f"and alerts the SNS topic {trail['SnsTopicARN']} instead of "
            f"{CLOUDTRAIL_SNS_TOPIC_ARN}")
    elif trail['IncludeGlobalServiceEvents'] is not True:
        raise Exception(
            f"CloudTrail sends to {CLOUDTRAIL_BUCKET} but it is misconfigured "
            f"and isn't including Global Service events like IAM")
    elif trail['IsMultiRegionTrail'] is not True:
        raise Exception(
            f"CloudTrail sends to {CLOUDTRAIL_BUCKET} but it is misconfigured "
            f"and isn't enabled multi region")
    elif kms_account is not None and kms_account != storage_account:
        raise Exception(
            f"CloudTrail sends to {CLOUDTRAIL_BUCKET} but it is misconfigured "
            f"and is encrypting the logs with a foreign KMS key")
    else:
        return True


def get_cloudtrail_accounts_by_query(
        security_audit_roles,
        session_name, policy) -> Tuple[Set, dict]:
    """Assume an IAM role in each account to test for misconfigurations

    This iterates over a list of IAM Roles, assuming each role, and fetching
    the CloudTrail trails in each account. It then checks each trail with
    is_cloudtrail_valid.

    :param security_audit_roles: List of AWS IAM roles to use to query
        CloudTrail
    :param session_name: User definable name to label the session with
    :param policy: IAM policy to constrain the permissions available from the
        role
    :return: A tuple of a set of the AWS account IDs of accounts with correctly
        configured CloudTrail and dict of accounts with misconfigured
        CloudTrail with the account ID as the key and the error message as the
        value
    """
    conforming_cloudtrail_account_ids = set()
    misconfigured_cloudtrail_accounts = {}
    for role_arn in security_audit_roles:
        account_id = role_arn.split(':')[4]
        credentials = get_credentials(role_arn, session_name, policy)
        del (credentials['expiration'])
        trails = get_paginated_results(
            'cloudtrail', 'list_trails', 'Trails', credentials)
        client = boto3.client('cloudtrail', **credentials)
        # Yes the argument "trailNameList" has weird capitalization and implies
        # that it accepts a list of names, not ARNs, but it actually accepts
        # either
        response = client.describe_trails(
            trailNameList=[x['TrailARN'] for x in trails]
        )
        trail_found = False
        for trail in response['trailList']:
            try:
                if is_cloudtrail_valid(trail):
                    trail_found = True
            except Exception as e:
                print(f"Exception raised in {account_id} : {e}")
                misconfigured_cloudtrail_accounts[account_id] = e
                break
        if trail_found:
            conforming_cloudtrail_account_ids.add(account_id)
    return (conforming_cloudtrail_account_ids,
            misconfigured_cloudtrail_accounts)


def get_cloudtrail_regions() -> List[str]:
    """Return an ordered list of AWS regions that could have a CloudTrail

    This is meant to create a list of regions that could contain a CloudTrail
    ordered by most likely to least likely based on Mozilla's usage. This is
    to try to find the region with the global CloudTrail definition fastest
    by checking the most likely regions first.

    :return: List of AWS regions
    """
    from boto3.session import Session
    cloudtrail_regions = Session().get_available_regions('cloudtrail')
    order_of_regions = [
        'us-west-2',
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'eu-central-1',
        'eu-north-1',
        'eu-west-1',
        'eu-west-2',
        'eu-west-3',
        'ap-east-1',
        'ap-northeast-1',
        'ap-northeast-2',
        'ap-south-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'ca-central-1',
        'me-south-1',
        'sa-east-1',
    ]
    remaining_regions = set(cloudtrail_regions) - set(order_of_regions)
    order_of_regions.extend(list(remaining_regions))
    return order_of_regions


def s3_has_cloudtrail_files(
        credentials, account_prefix, order_of_regions) -> bool:
    """Looks at files in S3 bucket to infer if CloudTrail is active

    This will not test if an attacker has encrypted the logs, or if Global
    Service Events (IAM events) are missing.

    Checks if a CloudTrail log file for a given account has been written in the
    last day.

    :param credentials: AWS STS credential dict
    :param account_prefix: S3 Bucket object prefix
    :param order_of_regions: Ordered list of regions that support CloudTrail
    :return: True if S3 contains a CloudTrail log from within the last day or
        False if not
    """
    date_suffixes = [
        (datetime.now() - timedelta(days=x)).strftime("%Y/%m")
        for x in range(0, 1)]
    for region in order_of_regions:
        prefixes = [
            f"{account_prefix}{region}/{date_suffix}/"
            for date_suffix in date_suffixes]
        for prefix in prefixes:
            try:
                get_paginated_results(
                    's3', 'list_objects_v2', 'CommonPrefixes', credentials,
                    {'Bucket': CLOUDTRAIL_BUCKET,
                     'Delimiter': '/',
                     'Prefix': prefix})
            except KeyError:
                # No CloudTrail data within the time window in this region
                pass
            else:
                return True
    return False


def get_accounts_missing_cloudtrail_by_file(account_ids) -> Set[str]:
    """Scan a CloudTrail S3 bucket for recent logs for a set of accounts

    Given a set of account_ids, scan an S3 bucket for recent CloudTrail logs
    from all accounts. Return a set of all account IDs which don't have recent
    CloudTrail logs in S3

    :param account_ids: List of AWS account IDs
    :return: Set of AWS account IDs
    """
    cloudtrail_bucket_name = CLOUDTRAIL_BUCKET
    order_of_regions = get_cloudtrail_regions()
    credentials = get_credentials(
        CLOUDTRAIL_READER_ROLE,
        'CheckForMissingRoles-CloudTrailReader',
        '{"Version":"2012-10-17","Statement":[{"Sid":"ListBucket","Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}'
    )
    del(credentials['expiration'])
    response = get_paginated_results(
        's3', 'list_objects_v2', 'CommonPrefixes', credentials,
        {'Bucket': cloudtrail_bucket_name,
         'Delimiter': '/',
         'Prefix': 'AWSLogs/'})
    account_prefix_list = [f"{x['Prefix']}CloudTrail/" for x in response if x['Prefix'].split('/')[1] in account_ids]

    accounts_with_cloudtrail_files = set()

    for account_prefix in account_prefix_list:
        account_id = account_prefix.split('/')[1]

        try:
            response = get_paginated_results(
                's3', 'list_objects_v2', 'CommonPrefixes', credentials,
                {'Bucket': cloudtrail_bucket_name,
                 'Delimiter': '/',
                 'Prefix': account_prefix})
        except KeyError:
            # Missing CloudTrail
            pass
        else:
            account_region_list = [x['Prefix'].split('/')[3] for x in response]
            if not account_region_list:
                # This account doesn't have any regions in it's CloudTrail path
                continue

            if s3_has_cloudtrail_files(
                    credentials,
                    account_prefix,
                    [x for x in order_of_regions if x in account_region_list]):
                accounts_with_cloudtrail_files.add(account_id)

    print(f"after checking these prefixes {account_prefix_list} for CloudTrail by looking at the files, we found these accounts with recent cloudtrailfiles : {accounts_with_cloudtrail_files}")
    return account_ids - accounts_with_cloudtrail_files


def get_guardduty_members() -> Set[str]:
    """Get all enabled GuardDuty members of the current AWS account GuardDuty parent

    :return: Set of AWS account IDs
    """
    detectors = get_paginated_results('guardduty', 'list_detectors', 'DetectorIds')
    client = boto3.client('guardduty')
    response = client.list_members(DetectorId=detectors[0])
    return set(x['AccountId'] for x in response['Members'] if x['RelationshipStatus'] == 'Enabled')


def print_account_list(accounts, all_accounts) -> None:
    """Print a list of accounts with ID Name : Organization

    :param accounts: List of account IDs
    :param all_accounts: Dict with a key of the account ID and value of a dict
        of information about the account
    :return: None
    """
    for account in sorted(list(accounts), key=lambda x: all_accounts[x]['Name']):
        print(f"{all_accounts[account]['Id']} ({all_accounts[account]['Name']}) : {all_accounts[account]['Organization']}")


def get_accounts_with_iam_users(security_audit_roles):
    session_name = 'CheckForMissingRoles-IAMUserPasswordChecker'
    policy = '{"Version":"2012-10-17","Statement":[{"Sid":"ListUsers","Effect":"Allow","Action":["IAM:ListUsers"],"Resource":"*"}]}'
    for role_arn in security_audit_roles:
        account_id = role_arn.split(':')[4]
        credentials = get_credentials(role_arn, session_name, policy)
        del (credentials['expiration'])
        users = get_paginated_results('iam', 'list_users', 'Users')

    # TODO
    # It would be nice to determine what IAM users have passwords, but it looks like only credential report
    # can provide that
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
    # and our security audit role currently doesn't grant that
    # we'd have to deploy https://github.com/mozilla/security/issues/60 to accounts

    # This function is incomplete


def main():
    security_audit_roles = get_role_arns(
        SECURITY_AUDIT_ROLE_TABLE_CATEGORY,
        SECURITY_AUDIT_ROLE_TABLE_ATTRIBUTE)
    cloudtrail_query_session_name = 'CheckForMissingRoles-CloudTrailChecker'
    cloudtrail_query_policy = '{"Version":"2012-10-17","Statement":[{"Sid":"ListTrails","Effect":"Allow","Action":["cloudtrail:ListTrails","cloudtrail:DescribeTrails"],"Resource":"*"}]}'
    print('Caching security audit credentials')
    security_audit_failures = cache_security_audit_credentials(
        security_audit_roles,
        cloudtrail_query_session_name, cloudtrail_query_policy)
    if security_audit_failures:
        print(f"security audit role failures : {security_audit_failures}")
    security_audit_roles = [x for x in security_audit_roles
                            if x not in security_audit_failures.keys()]
    print('Fetching CloudTrail information')
    conforming_cloudtrail_account_ids, misconfigured_cloudtrail_accounts = get_cloudtrail_accounts_by_query(
        security_audit_roles, cloudtrail_query_session_name, cloudtrail_query_policy)
    print("Conforming CloudTrail accounts")
    print(conforming_cloudtrail_account_ids)
    if misconfigured_cloudtrail_accounts:
        print("Misconfigured CloudTrail accounts")
        print(misconfigured_cloudtrail_accounts)

    print('Fetching child accounts from organizations')
    all_accounts = get_org_accounts()

    print('Inferring CloudTrail information from S3 files')
    accounts_missing_cloudtrail_by_file = get_accounts_missing_cloudtrail_by_file(
        all_accounts.keys() - conforming_cloudtrail_account_ids)

    guardduty_roles = get_role_arns(
        GUARDDUTY_ROLE_TABLE_CATEGORY, GUARDDUTY_ROLE_TABLE_ATTRIBUTE)
    accounts_with_security_audit_roles = [
        x.split(':')[4] for x in security_audit_roles]
    accounts_with_guardduty_roles = [x.split(':')[4] for x in guardduty_roles]
    accounts_with_guardduty_relationship = get_guardduty_members()
    accounts_with_sso_roles = get_sso_accounts()

    accounts_missing_security_audit_roles = all_accounts.keys() - set(accounts_with_security_audit_roles)
    accounts_missing_guardduty_roles = all_accounts.keys() - set(accounts_with_guardduty_roles)
    accounts_missing_guardduty_relationship = all_accounts.keys() - set(accounts_with_guardduty_relationship)
    accounts_missing_sso = all_accounts.keys() - set(accounts_with_sso_roles)

    print('Accounts missing security audit roles')
    print_account_list(accounts_missing_security_audit_roles, all_accounts)
    print("\nAccounts missing GuardDuty role")
    print_account_list(accounts_missing_guardduty_roles, all_accounts)
    print("\nAccounts missing GuardDuty relationship")
    print_account_list(accounts_missing_guardduty_relationship, all_accounts)
    print("\nAccounts missing SSO")
    print_account_list(accounts_missing_sso, all_accounts)
    print("\nAccounts with a misconfigured CloudTrail")
    print_account_list(misconfigured_cloudtrail_accounts, all_accounts)
    print("\nAccounts missing CloudTrail")
    print_account_list(accounts_missing_cloudtrail_by_file, all_accounts)


if __name__ == "__main__":
    main()