from django.urls import path

from . import views
from .my_views import state_views
from .my_views import func_views
from .my_views import variable_views

urlpatterns = [
    path('', views.index, name='index'),

    # 固件文件头自动解码或解析
    path('/decode', views.binwalk_scan_signature, name='binwalk_scan_signature'),

    # 架构识别
    path('/arch', views.binwalk_scan_opcodes, name='binwalk_scan_opcodes'),

    # 抽取文件
    path('/extract', views.binwalk_file_extract, name='binwalk_file_extract'),

    # 测试 binwalk
    path('/test_binwalk', views.binwalk_file_test, name='binwalk_file_test'),

    # 转换成中间代码
    path('/convert_code', views.angr_convert_code, name='angr_convert_code'),

    # 转换成汇编代码
    # path('/convert_asm', views.angr_convert_asm, name='angr_convert_asm'),

    # 函数识别
    path('/recognize_func', views.angr_recognize_func, name='angr_recognize_func'),

    #
    # new interface
    #

    # 状态机信息
    path('/state', state_views.entry_state_info, name='entry_state_info'),

    # 函数列表
    path('/functions', func_views.fw_functions_list, name='fw_functions_list'),

    # 函数后继调用
    path('/functions/successors', func_views.func_successors, name='func_successors'),

    # 指定函数的汇编代码
    path('/functions/asm', func_views.func_asm, name='func_asm'),

    # 指定函数的中间代码
    path('/functions/vex', func_views.func_vex, name='func_vex'),

]