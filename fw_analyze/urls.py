from django.urls import path

from . import views
from .my_views import state_views
from .my_views import old_func_views
from .my_views import old_func_async_views
from .my_views import analyze_cfg_view
from .my_views import parse_cfg_view
from .my_views import variable_views

urlpatterns = [

    # =========================================================================
    # 正式指令部分

    # 启动 cfg 分析任务，并保存分析结果到数据库
    path('task/analyze_cfg', analyze_cfg_view.analyze_cfg, name='task_analyze_cfg'),

    # 获取获取函数列表
    path('cfg/func_list', parse_cfg_view.cfg_file_list, name='parse_cfg_file_list'),

    # 获取函数信息，包含诸如：汇编代码、中间代码、后继调用等
    # path('cfg/func_info', old_func_async_views.async_function_info, name='async_function_info'),

    # =========================================================================
    # 以下部分均为测试指令

    path('', views.index, name='index'),

    # 固件文件头自动解码或解析
    path('decode', views.binwalk_scan_signature, name='binwalk_scan_signature'),
    path('decodeEx', views.binwalk_scan_signatureEx, name='binwalk_scan_signature'),

    # 架构识别
    path('arch', views.binwalk_scan_opcodes, name='binwalk_scan_opcodes'),

    # 抽取文件
    path('extract', views.binwalk_file_extract, name='binwalk_file_extract'),
    path('extractEx', views.binwalk_file_extractEx, name='binwalk_file_extract'),

    # 测试 binwalk
    path('test_binwalk', views.binwalk_file_test, name='binwalk_file_test'),

    # 转换成中间代码
    path('convert_code', views.angr_convert_code, name='angr_convert_code'),

    # 转换成汇编代码
    # path('/convert_asm', views.angr_convert_asm, name='angr_convert_asm'),

    # 函数识别
    path('recognize_func', views.angr_recognize_func, name='angr_recognize_func'),

    #
    # 函数及状态机基本分析：同步调用接口
    #

    # 状态机信息
    path('state', state_views.entry_state_info, name='entry_state_info'),

    # 函数列表
    path('functions', old_func_views.fw_functions_list, name='fw_functions_list'),

    # 函数后继调用
    path('functions/successors', old_func_views.func_successors, name='func_successors'),

    # 指定函数的汇编代码
    path('functions/asm', old_func_views.func_asm, name='func_asm'),

    # 指定函数的中间代码
    path('functions/vex', old_func_views.func_vex, name='func_vex'),


    #
    # 函数分析：异步调用接口
    #

    # 异步获取函数列表
    path('async_funcs/list', old_func_async_views.async_fw_functions_list, name='async_fw_functions_list'),

    # 异步获取函数信息，包含诸如：汇编代码、中间代码、后继调用等
    path('async_funcs/func_info', old_func_async_views.async_function_info, name='async_function_info'),

    # 异步绘制函数调用关系图
    path('async_funcs/call_graph', old_func_async_views.async_function_call_graph, name='async_function_call_graph'),

    # 读取任务结果
    path('task_result', old_func_async_views.get_task_result, name='async_fw_functions_list'),

]