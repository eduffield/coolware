# CloudPeek
Cloud Security Reporting System

Reports that allow you to scale with confidence.

Supports security inspections for AWS, Azure, and GCP providers.

## System Requirements
- [Python 3.9 or later](https://www.python.org/downloads/)
- CLI for each provider must be installed seperately and configured. See: [AWS](https://aws.amazon.com/cli/), [Azure](https://learn.microsoft.com/en-us/cli/azure/), [GCP](https://cloud.google.com/sdk/gcloud)

## Running a report
```
python3 main.py
```
Open your browser to http://127.0.0.1:5000/

## Running Tests With Terraform

1. Install Terraform from [here.](https://developer.hashicorp.com/terraform/install)
2. Create a .pem key for your provider and place it in the same directory as main.tf
3. Run 'terraform init' in the directory of the demo you wish to run. Ex. ("aws ec2 create-key-pair --key-name example-key --query 'KeyMaterial' --output text > example-key.pem")
4. Run 'terraform plan'
5. Run 'terraform apply'
6. Run the tool.
7. Once the report is done generating, run 'terraform destroy'



## Developed by:
Evan Duffield
Dylan Morris
Bennett Wiley
