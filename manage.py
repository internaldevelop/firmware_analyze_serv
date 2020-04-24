#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
import py_eureka_client.eureka_client as eureka_client
from django.conf import settings
import utils.sys.config
from utils.db.mongodb.sys_config import SystemConfig
from utils.gadget.general import SysUtils
from utils.gadget.my_path import MyPath


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
                                           instance_port=your_rest_server_port)
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

        #
        # syslog = eureka_client.do_service("SYSTEM-LOG", "/sys_log/add",
        #                                # 返回类型，默认为 `string`，可以传入 `json`，如果传入值是 `json`，那么该方法会返回一个 `dict` 对象
        #                                return_type="string")
        # print("system-log:" + syslog)
        settings.FW_PATH = MyPath.firmware()
        SysUtils.check_filepath(settings.FW_PATH)
        SysUtils.check_filepath(MyPath.temporary())




    except ZeroDivisionError as e:
        print('except:', e)

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

