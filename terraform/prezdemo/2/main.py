# main.py
from datetime import datetime
from Report import Report
import AWS
# import Azure  # Assume similar structure for Azure.py
# import GCP    # Assume similar structure for GCP.py

def main():
    dt_string = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report = Report(report_date=dt_string)

    # Scan resources from different providers
    AWS.scan_aws_resources(report)
    # Azure.scan_azure_resources(report)  # Uncomment and implement similar function in Azure.py
    # GCP.scan_gcp_resources(report)     # Uncomment and implement similar function in GCP.py

    # Print and save report
    report.list_issues()
    report.write_to_json(f"comprehensive_cloud_report_{dt_string}.json")

if __name__ == "__main__":
    main()
