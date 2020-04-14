from django.urls import path

from .views import info_view
from .views import sys_config_view
from .views import system_view

urlpatterns = [
    # 系统信息
    path('info', info_view.system_info, name='system_info'),

    # 初步检验文件 -- 多用于测试
    path('check_file', info_view.check_file, name='check_file'),

    # 系统配置重置为出厂参数
    path('default_config', sys_config_view.reset_default_sys_config, name='reset_default_sys_config'),

    # 写入新的系统配置
    path('write_config', sys_config_view.write_sys_config, name='write_sys_config'),

    # 读取系统配置
    path('read_config', sys_config_view.read_sys_config, name='read_sys_config'),

    # 清空固件包及其文件（pack_type：1=实体包；2=虚拟包；不填或无此参数表示1+2，其它值不处理。）
    path('clear_packs', system_view.system_clear_packs, name='system_clear_packs'),

    # 加载缺省固件包（pack_type：1=实体包；2=虚拟包；不填或无此参数表示1+2，其它值不处理。）
    path('load_default_packs', system_view.system_load_default_packs, name='system_load_default_packs'),
]
