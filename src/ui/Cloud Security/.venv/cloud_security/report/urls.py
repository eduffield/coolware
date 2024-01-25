from django.urls import path
from . import views

urlpatterns = [
    path('report/', views.report, name='report'),
    path('report/report_data/<int:id>', views.report_data, name='report_data')
]