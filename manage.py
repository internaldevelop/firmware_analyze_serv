#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
import py_eureka_client.eureka_client as eureka_client
from django.conf import settings
import utils.sys.config
from fw_analyze.service.cfg_analyze_service import CfgAnalyzeService
# from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.sys_config import SystemConfig
from utils.gadget.general import SysUtils
from utils.gadget.my_path import MyPath
# from utils.task.my_task import MyTask
# from utils.task.task_type import TaskType


def main():
    # 加载系统配置，写入到 redis 缓存中
    SystemConfig.cache_load()

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'firmware_analyze_serv.settings')
    try:

        # EUREKA接口
        eureka_server_list = utils.sys.config.eureka_server_list
        your_rest_server_host = utils.sys.config.your_rest_server_host
        your_rest_server_port = utils.sys.config.your_rest_server_port

        # The flowing code will register your server to eureka server and also start to send heartbeat every 30 seconds
        # 注册服务
        eureka_client.init_registry_client(eureka_server=eureka_server_list,
                                           app_name="firmware-analyze",
                                           instance_host=your_rest_server_host,
                                           instance_port=your_rest_server_port,

                                           # 测试阶段建议添加以下两个参数
                                           renewal_interval_in_secs=20,# Eureka客户端向服务端发送心跳的时间间隔，单位为秒（客户端告诉服务端自己会按照该规则），默认30
                                           duration_in_secs=20)# Eureka服务端在收到最后一次心跳之后等待的时间上限，单位为秒，超过则剔除（客户端告诉服务端按照此规则等待自己），默认90
        # 发现服务
        # you can reuse the eureka_server_list which you used in registry client
        listservice = eureka_client.init_discovery_client(eureka_server_list)

        # 调用服务 SYSTEM-CODE
        res = eureka_client.do_service("SYSTEM-CODE", "/sys_code/run_status",
                                       # 返回类型，默认为 `string`，可以传入 `json`，如果传入值是 `json`，那么该方法会返回一个 `dict` 对象
                                       return_type="string")
        print("result of other service" + res)
        # 获取错误码
        syscode = eureka_client.do_service("SYSTEM-CODE", "/sys_code/err_codes/all",
                                           # 返回类型，默认为 `string`，可以传入 `json`，如果传入值是 `json`，那么该方法会返回一个 `dict` 对象
                                           return_type="json")
        # string_Sys_code_err = eureka_client.do_service("SYSTEM-CODE", "/sys_code/err_codes/all",
        #                                # 返回类型，默认为 `string`，可以传入 `json`，如果传入值是 `json`，那么该方法会返回一个 `dict` 对象
        #                                return_type="string")
        settings.SYS_CODE = syscode['payload']

        utils.sys.config.g_eureka_client = eureka_client

        #
        # syslog = eureka_client.do_service("SYSTEM-LOG", "/sys_log/add",
        #                                # 返回类型，默认为 `string`，可以传入 `json`，如果传入值是 `json`，那么该方法会返回一个 `dict` 对象
        #                                return_type="string")
        # print("system-log:" + syslog)

        # for initial
        settings.FW_PATH = MyPath.firmware()
        SysUtils.check_filepath(settings.FW_PATH)
        SysUtils.check_filepath(MyPath.temporary())
        SysUtils.check_filepath(MyPath.component())


        # 启动自动CFG分析任务
        # task = MyTask(_proc_cfg_analyze, )


    except ZeroDivisionError as e:
        print('except:', e)
        eureka_client.stop()

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


def _proc_cfg_analyze(task_id):
    # 启动分析任务
    CfgAnalyzeService.auto_cfg_task(task_id)


if __name__ == '__main__':
    main()
    eureka_client.stop()

