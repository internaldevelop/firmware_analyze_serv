from django.urls import path

from . import views
from .my_views import state_views
from .my_views import old_func_views
from .my_views import old_func_async_views
from .my_views import analyze_cfg_view
from .my_views import parse_cfg_view
from .my_views import task_view
from .my_views import pack_view
from .my_views import variable_views

urlpatterns = [

    # =========================================================================
    # 正式指令部分

    # 启动 cfg 分析任务，并保存分析结果到数据库
    path('task/analyze_cfg', analyze_cfg_view.analyze_cfg, name='task_analyze_cfg'),

    # 读取任务结果
    path('task/query', task_view.get_task_result, name='task_query'),

    # 读取全部任务结果
    path('task/query_all', task_view.get_all_task_result, name='task_query_all'),

    # 读取组件任务结果
    path('task/query_component', task_view.query_component, name='task_query_component'),

    # 停止任务
    path('task/stop', task_view.stop_task, name='task_stop'),

    # 读取指定 pack 的任务
    path('task/search_by_pack', task_view.search_tasks_by_pack, name='search_tasks_by_pack'),

    # 读取指定 文件 的任务
    path('task/search_by_file', task_view.search_tasks_by_file, name='search_tasks_by_file'),

    # 获取函数列表
    path('cfg/func_list', parse_cfg_view.cfg_func_list, name='parse_cfg_func_list'),

    # 获取指定函数的 call-graph
    path('cfg/call_graph_a', parse_cfg_view.call_graph_a, name='parse_cfg_call_graph_a'),

    # 获取指定函数的 control_flow_graph
    path('cfg/cfg_graph', parse_cfg_view.control_flow_graph, name='parse_cfg_control_flow_graph'),

    # 获取指定函数的 control_dependence_graph
    path('cfg/cdg_graph', parse_cfg_view.control_dependence_graph, name='parse_cfg_control_dependence_graph'),

    # 获取函数信息，包含诸如：汇编代码、中间代码、后继调用等
    path('cfg/func_info', parse_cfg_view.function_info, name='parse_cfg_function_info'),

    # 获取函数属性，包含：参数、返回、地址等
    path('cfg/func_props', parse_cfg_view.function_props, name='parse_cfg_function_props'),

    # 查询所有固件包信息
    path('pack/all', pack_view.all_packs_info, name='query_all_packs_info'),

    # 查询指定固件包信息
    path('pack/info', pack_view.pack_info, name='query_pack_info'),

    # 编辑指定固件包信息 厂商 型号
    path('pack/edit', pack_view.pack_edit, name='query_pack_edit'),

    # 删除指定固件包
    path('pack/delete', pack_view.pack_delete, name='query_pack_info'),

    # 查询指定固件包中所含的执行文件目录树
    path('pack/exec_files_tree', pack_view.pack_exec_files_tree, name='query_pack_exec_files_tree'),

    # 查询所有组件文件目录树
    path('pack/com_files_tree', pack_view.com_files_tree, name='query_com_files_tree'),

    # 9.9 组件源码文件目录树
    path('pack/com_sourcecode_files_tree', pack_view.com_sourcecode_files_tree, name='query_com_sourcecode_files_tree'),

    # 查询所有组件文件列表
    path('pack/com_files_list', pack_view.com_files_list, name='query_com_files_list'),

    # 提取解析变量
    path('vars/extract', variable_views.analyze_extract_vars, name='query_analyze_extract_vars'),

    # 组件自动漏洞关联
    path('com/auto_vuler_association', pack_view.auto_vuler_association, name='async_com_vuler_association'),

    # 检测缓冲区溢出漏洞
    path('task/analyze_vuler', parse_cfg_view.analyze_vuler, name='task_analyze_vul'),

    # =========================================================================
    # 以下部分均为测试指令


    # 启动 cfg 分析任务，并保存分析结果到数据库
    path('task/analyze_cfg_auto', analyze_cfg_view.analyze_cfg_auto, name='task_analyze_cfg'),

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


]