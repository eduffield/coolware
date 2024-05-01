# AWS.py
import boto3
from datetime import datetime

def scan_aws_resources(report):
    ec2 = boto3.client('ec2')
    s3 = boto3.client('s3')

    # Security Groups
    security_groups = get_security_groups(ec2)
    check_public_access_sg(report, security_groups)

    # S3 Buckets
    check_s3_buckets(s3)

def get_security_groups(ec2):
    security_groups = []
    try:
        response = ec2.describe_security_groups()
        for sg in response['SecurityGroups']:
            ingress_rules = [{
                'FromPort': rule.get('FromPort', 'All'),
                'ToPort': rule.get('ToPort', 'All'),
                'IpProtocol': rule.get('IpProtocol', '-1'),
                'IpRanges': [ip['CidrIp'] for ip in rule.get('IpRanges', [])]
            } for rule in sg.get('IpPermissions', [])]
            security_groups.append({'GroupId': sg['GroupId'], 'GroupName': sg['GroupName'], 'IngressRules': ingress_rules})
    except Exception as e:
        print(f"Error fetching security groups: {e}")
    return security_groups

def check_public_access_sg(report, security_groups):
    for sg in security_groups:
        for rule in sg['IngressRules']:
            if '0.0.0.0/0' in rule['IpRanges']:
                issue = f"Security Group '{sg['GroupName']}' allows public access."
                remediation = "Restrict access to known IPs or internal networks."
                report.add_issue(severity=2, issue=issue, remediation=remediation)

def check_s3_buckets(s3):
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']
            bucket_acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in bucket_acl['Grants']:
                if grant['Grantee'].get('Type') == 'Group' and grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    issue = f"S3 Bucket '{bucket_name}' is publicly accessible."
                    remediation = "Modify the bucket ACL to restrict public access."
                    report.add_issue(severity=3, issue=issue, remediation=remediation)
    except Exception as e:
        print(f"Error checking S3 buckets: {e}")

