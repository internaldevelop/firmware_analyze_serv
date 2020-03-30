import utils.sys.config
from utils.gadget.general import SysUtils
from utils.gadget.strutil import StrUtils
from utils.db.sys_config import SystemConfig


# 日志记录集合
logs_coll = utils.sys.config.g_logs_coll


class LogRecords:
    def __init__(self):
        return

    @staticmethod
    def save(log, category='debug', action='普通操作', desc='操作日志', user='guest'):
        # 根据系统配置，不在配置参数中的日志类型，不做日志记录
        if not SystemConfig.match_log_category(category):
            return

        log_uuid = StrUtils.uuid_str()
        create_time = SysUtils.get_now_time()
        logs_coll.update_one({'uuid': log_uuid},
                             {'$set': {
                                 'uuid': log_uuid,
                                 'category': category,
                                 'action': action,
                                 'description': desc,
                                 'content': log,
                                 'user_account': user,
                                 'create_time': create_time
                             }}, True)
        return
