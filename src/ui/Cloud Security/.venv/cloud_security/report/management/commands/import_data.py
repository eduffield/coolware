# your_app/management/commands/import_data.py
import os
import json
from report.models import ReportData
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Import data from JSON files into Django model'

    def handle(self, *args, **options):
        folder_path = 'report/report_output'

        for filename in os.listdir(folder_path):
            if filename.endswith('.json'):
                file_path = os.path.join(folder_path, filename)
                with open(file_path, 'r') as file:
                    data = json.load(file)
                    
                    report_contents = data.get("Report Contents", [])

                    for item in report_contents:
                        data = ReportData(severity = item["Severity"],issue = item["Issue"],remediation = item["Remediation"])
                        data.save()

        self.stdout.write(self.style.SUCCESS('Data imported successfully'))
