from django.http import HttpResponse
from django.template import loader
from .models import ReportData

#def report(request):
  #template = loader.get_template('page.html')
  #return HttpResponse(template.render())

def report(request):
    full_report = ReportData.objects.all().values
    template = loader.get_template('full_report.html')
    context = {
        'full_report': full_report,
    }
    return HttpResponse(template.render(context, request))

def report_data(request, id):
    data = ReportData.objects.get(id=id)
    template = loader.get_template('report_data.html')
    context = {
        'data': data,
    }
    return HttpResponse(template.render(context, request))