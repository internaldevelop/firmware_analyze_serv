from django.urls import path

from . import views

urlpatterns = [

    # 报告
    path('pdf/create_report', views.create_report, name='create_report'),
    path('pdf/get_report_pdf', views.get_report_pdf, name='get_report_pdf'),
    path('pdf/download_report', views.download_report, name='download_report'),

]
