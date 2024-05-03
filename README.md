# CloudPeek
Cloud Security Reporting System

Reports that allow you to scale with confidence.

Supports security inspections for AWS, Azure, and GCP providers.

CloudPeek uses the MITRE ATT&CK Matrix to protect your servers, databases, and networks.

## System Requirements
- [Python 3.9 or later](https://www.python.org/downloads/)
- CLI for each provider that you use must be installed seperately and configured. See: [AWS](https://aws.amazon.com/cli/), [Azure](https://learn.microsoft.com/en-us/cli/azure/), [GCP](https://cloud.google.com/sdk/gcloud)

## Running the program
```
cd ./src/final

# Install the requirements

pip install -r requirements.txt

# View reports

python3 main.py viewreport

# Generate a new report

python3 main.py makereport

```
Open your browser to http://127.0.0.1:5000/

## Running Tests With Terraform

Note: Please have a provider CLI installed and configured before using terraform.

1. Install Terraform from [here.](https://developer.hashicorp.com/terraform/install)
2. Run 'terraform init' in the directory of the demo you wish to run.
3. Run 'terraform plan'.
4. Run 'terraform apply'.
5. Run the tool.
6. Once the report is done generating, run 'terraform destroy'.
7. Check the expected report with the generated report with the pytest.py file in the terraform directory.


## Developed by:
Evan Duffield
Dylan Morris
Bennett Wiley
