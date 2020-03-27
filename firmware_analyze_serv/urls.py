"""firmware_analyze_serv URL Configuration

The `urlpatterns` list routes URLs to my_views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function my_views
    1. Add an import:  from my_app import my_views
    2. Add a URL to urlpatterns:  path('', my_views.home, name='home')
Class-based my_views
    1. Add an import:  from other_app.my_views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('system/', include('system.urls')),
    path('admin', admin.site.urls),
    path('fw_fetch/', include('fw_fetch.urls')),
    path('fw_analyze/', include('fw_analyze.urls')),

]
