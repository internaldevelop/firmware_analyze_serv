from django.urls import path

from .views import info_view

urlpatterns = [
    path('info', info_view.system_info, name='system_info'),

]