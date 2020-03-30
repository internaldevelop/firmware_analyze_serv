from django.urls import path

from .views import info_view
from .views import sys_config_view

urlpatterns = [
    # 系统信息
    path('info', info_view.system_info, name='system_info'),

    # 系统配置重置为出厂参数
    path('default_config', sys_config_view.reset_default_sys_config, name='reset_default_sys_config'),

    # 写入新的系统配置
    path('write_config', sys_config_view.write_sys_config, name='write_sys_config'),

    # 读取系统配置
    path('read_config', sys_config_view.read_sys_config, name='read_sys_config'),

]
