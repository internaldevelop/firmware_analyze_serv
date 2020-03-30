from common.db.sys_config import SystemConfig
from common.db.logs import LogRecords
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from common.utils.http_request import req_get_param, req_post_param


def reset_default_sys_config(request):
    # 数据库中写入默认出厂参数
    SystemConfig.write_db(None)

    # 重新加载新的配置参数（出厂设置）到缓存
    config = SystemConfig.cache_load()

    # 保存操作日志
    LogRecords.save({'data': config}, category='system_config', action='重置系统配置',
                    desc='重置系统配置为出厂模式')

    return sys_app_ok_p(config)


def write_sys_config(request):
    # 从请求中取参数：新的系统配置
    new_config_str = req_post_param(request, 'sys_config')
    new_config = eval(new_config_str)

    # 数据库中写入系统配置参数
    SystemConfig.write_db(new_config)

    # 重新加载新的配置参数到缓存
    config = SystemConfig.cache_load()

    # 保存操作日志
    LogRecords.save({'data': config}, category='system_config', action='更新系统配置',
                    desc='更新系统各项配置参数')

    return sys_app_ok_p(config)


def read_sys_config(request):
    # 从数据库中读取系统配置
    config = SystemConfig.read_db()

    # 保存操作日志
    LogRecords.save({'data': config}, category='system_config', action='读取系统配置',
                    desc='读取系统各项配置参数')

    return sys_app_ok_p(config)
