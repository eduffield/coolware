import boto3
from datetime import datetime
from Report import Report, Resource

def scan_aws_resources(report, region="us-east-1"):
    try:
        ec2 = boto3.client('ec2', region_name=region)
        s3 = boto3.client('s3', region_name=region)
        rds = boto3.client('rds', region_name=region)

        security_groups = get_security_groups(ec2)
        check_public_access_sg(report, security_groups, region)
        check_unencrypted_ebs_volumes(ec2, report, region)
        check_s3_buckets(s3, report, region)
        check_rds_instances(rds, report, region)
    except Exception as e:
        print(f"Can't connect to AWS: {e}")

def check_rds_instances(rds, report, region):
    try:
        dbs = rds.describe_db_instances()
        for db in dbs['DBInstances']:
            db_id = db['DBInstanceIdentifier']
            encryption_status = db['StorageEncrypted']
            auto_upgrade_status = db['AutoMinorVersionUpgrade']

            if not encryption_status:
                issue = f"RDS instance '{db_id}' storage is not encrypted."
                remediation = "Enable encryption for RDS instances to protect data at rest."
                affected_resources = [Resource(name=db_id, region=region, provider="AWS", service="RDS")]
                report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)
            
            if not auto_upgrade_status:
                issue = f"RDS instance '{db_id}' has automatic minor version upgrades disabled."
                remediation = "Enable automatic minor version upgrades to receive security patches."
                affected_resources = [Resource(name=db_id, region=region, provider="AWS", service="RDS")]
                report.add_issue(severity=2, issue=issue, remediation=remediation, affected_resources=affected_resources)
    except Exception as e:
        print(f"Error checking RDS instances: {e}")

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

def check_unencrypted_ebs_volumes(ec2, report, region):
    try:
        response = ec2.describe_volumes(Filters=[{'Name': 'encrypted', 'Values': ['false']}])
        for volume in response['Volumes']:
            issue = f"EBS volume '{volume['VolumeId']}' is not encrypted."
            remediation = "Encrypt EBS volumes to protect data at rest."
            affected_resources = [Resource(name=volume['VolumeId'], region=region, provider="AWS", service="EC2")]
            report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)
    except Exception as e:
        print(f"Error checking EBS volumes: {e}")

def check_public_access_sg(report, security_groups, region):
    for sg in security_groups:
        for rule in sg['IngressRules']:
            print(rule)
            if '0.0.0.0/0' in rule['IpRanges']:
                open_port = rule['FromPort']
                issue = f"Security Group '{sg['GroupName']}' allows public access on port {open_port}."
                remediation = "Restrict access to known IPs or internal networks."
                affected_resources = [
                    Resource(name=sg['GroupName'], region=region, provider="AWS", service="EC2")
                ]
                report.add_issue(severity=2, issue=issue, remediation=remediation, affected_resources=affected_resources)

def check_s3_buckets(s3, report, region):
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']
            bucket_acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in bucket_acl['Grants']:
                if grant['Grantee'].get('Type') == 'Group' and grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    issue = f"S3 Bucket '{bucket_name}' is publicly accessible."
                    remediation = "Modify the bucket ACL to restrict public access."
                    affected_resources = [
                        Resource(name=bucket_name, region=region, provider="AWS", service="S3")
                    ]
                    report.add_issue(severity=3, issue=issue, remediation=remediation, affected_resources=affected_resources)
    except Exception as e:
        print(f"Error checking S3 buckets: {e}")


