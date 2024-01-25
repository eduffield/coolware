from django.db import models

# Create your models here.
class ReportData(models.Model):
    severity = models.IntegerField()
    issue = models.CharField(max_length=255)
    remediation = models.TextField()