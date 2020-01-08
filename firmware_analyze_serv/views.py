from django.shortcuts import render
from django.conf import settings


def global_settings(request):
    return {
        'SYS_CODE': settings.SYS_CODE
    }

def global_fw_filepath(request):
    return {
        'FW_PATH': settings.FW_PATH
    }

def index(request):
    return render(request, 'index.html', locals())