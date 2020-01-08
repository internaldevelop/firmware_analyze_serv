from django.shortcuts import render
from django.conf import settings


def global_settings(request):
    return {
        'SYS_CODE': settings.SYS_CODE
    }


def index(request):
    return render(request, 'index.html', locals())