from google.oauth2 import service_account
from google.cloud import storage
from google.cloud import compute_v1
# from google.cloud import sqladmin_v1beta4
from google.cloud import container_v1
from Report import Report, Resource

def check_gcs_buckets(storage_client, report, project_id):
    buckets = storage_client.list_buckets(project=project_id)
    for bucket in buckets:
        iam_policy = bucket.get_iam_policy()
        for role, members in iam_policy.bindings.items():
            if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                issue = f"GCS Bucket '{bucket.name}' is publicly accessible."
                remediation = "Remove public access from the bucket IAM policy."
                report.add_issue(severity=4, issue=issue, remediation=remediation, affected_resources=[Resource(name=bucket.name, provider='Google Cloud', service='Google Cloud Storage', region='global')])

'''
def check_cloud_sql_instances(sql_client, project_id, report):
    request = sqladmin_v1beta4.SqlInstancesListRequest(project=project_id)
    instance_list = sql_client.list(request=request)
    for instance in instance_list.items:
        if not instance.settings.ip_configuration.require_ssl:
            issue = f"Cloud SQL instance '{instance.name}' does not require SSL for connections."
            remediation = "Enable SSL for all connections to this database instance."
            report.add_issue(
                severity=3,
                issue=issue,
                remediation=remediation,
                affected_resources=[Resource(name=instance.name, provider='Google Cloud', service='Google Cloud SQL', region='global')]
            )
'''
            
def check_gke_clusters(gke_client, project_id, report):
    request = container_v1.ListClustersRequest(project_id=project_id)
    clusters_list = gke_client.list_clusters(request=request)
    for cluster in clusters_list.clusters:
        if not cluster.private_cluster_config.enable_private_nodes:
            issue = f"Kubernetes cluster '{cluster.name}' is not configured as a private cluster."
            remediation = "Configure the cluster to use private nodes to enhance security."
            report.add_issue(
                severity=3,
                issue=issue,
                remediation=remediation,
                affected_resources=[Resource(name=cluster.name, provider='Google Cloud', service='Google Kubernetes Engine', region='global')]
            )

def check_gce_instances(compute_client, project_id, report):
    request = compute_v1.AggregatedListInstancesRequest(project=project_id)
    instance_aggregated_list = compute_client.aggregated_list(request=request)
    for location, response in instance_aggregated_list.items():
        if response.instances:
            for instance in response.instances:
                for disk in instance.disks:
                    if not disk.disk_encryption_key:
                        issue = f"Compute Engine instance '{instance.name}' has an unencrypted disk."
                        remediation = "Encrypt the disk using a customer-managed encryption key (CMEK)."
                        report.add_issue(
                            severity=4,
                            issue=issue,
                            remediation=remediation,
                            affected_resources=[Resource(name=instance.name, provider='Google Cloud', service='Google Compute Engine', region='global')]
                        )

def main(report):
    try:
        ### FIX LATER: Add some way for people to specify path on first start?
        credentials = service_account.Credentials.from_service_account_file(
            'path_to_your_service_account_key.json'
        )
        project_id = 'your_project_id'

        storage_client = storage.Client(credentials=credentials, project=project_id)
        compute_client = compute_v1.InstancesClient(credentials=credentials)
        # sql_client = sqladmin_v1beta4.SqlAdminServiceClient(credentials=credentials)
        gke_client = container_v1.ClusterManagerClient(credentials=credentials)

        check_gcs_buckets(storage_client, report, project_id)
        check_gce_instances(compute_client, project_id, report)
        # check_cloud_sql_instances(sql_client, project_id, report)
        check_gke_clusters(gke_client, project_id, report)

    except Exception as e:
        print(f"Couldn't connect to GCP. {e}")
        pass

