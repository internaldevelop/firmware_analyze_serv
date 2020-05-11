from utils.db.mongodb.sys_config import SystemConfig
from utils.db.mongodb.logs import LogRecords
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p
from utils.http.http_request import req_post_param, req_get_param

global false, null, true
false = null = true = ''

# 重置包含两件事：1. 重置管理员和审计员密码；2. 系统配置回到出厂缺省状态
def reset_default_sys_config(request):
    # 重置管理员和审计员密码

    # 数据库中写入默认出厂参数
    SystemConfig.write_db(None)

    # 重新加载新的配置参数（出厂设置）到缓存
    config = SystemConfig.cache_load()

    # 保存操作日志
    LogRecords.save(config, category='system_config', action='重置系统配置',
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
    LogRecords.save(config, category='system_config', action='更新系统配置',
                    desc='更新系统各项配置参数')

    return sys_app_ok_p(config)


def read_sys_config(request):
    read_all = ReqParams.one(request, 'all_config.int')

    # 从数据库中读取系统配置
    config = SystemConfig.read_db(read_all)

    # 保存操作日志
    LogRecords.save(config, category='system_config', action='读取系统配置',
                    desc='读取系统各项配置参数')

    return sys_app_ok_p(config)


def backup_config(request):
    # 从请求中取参数：新的系统配置
    new_config_key = req_post_param(request,'config_key')
    new_config_str = req_post_param(request, 'sys_config')
    new_config = eval(new_config_str)

    # 数据库中写入系统配置参数
    SystemConfig.backup_db(new_config_key,new_config)

    # 重新加载新的配置参数到缓存
    config = SystemConfig.cache_load()

    # 保存操作日志
    LogRecords.save(config, category='system_config', action='备份系统配置',
                    desc='备份系统各项配置参数')

    return sys_app_ok_p(config)

def recover_config(request):
    # 从请求中取参数：新的系统配置
    new_config_key = req_get_param(request, 'config_key')

    # 数据库中写入系统配置参数
    SystemConfig.recover_db(new_config_key)

    # 重新加载新的配置参数到缓存
    config = SystemConfig.cache_load()

    # 保存操作日志
    LogRecords.save(config, category='system_config', action='备份系统配置',
                    desc='备份系统各项配置参数')

    return sys_app_ok_p(config)

