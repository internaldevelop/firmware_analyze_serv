from utils.cache.redis import MyRedis
import utils.sys.config


# 系统字典集合
sys_dict_coll = utils.sys.config.g_sys_dict_coll


class SystemConfig:
    # @staticmethod
    # def _default_log_categories():
    #     return [{'on': True, 'category': 'analysis', 'description': '文件解析操作'},
    #             {'on': True, 'category': 'system_config', 'description': '系统配置参数设置'},
    #             {'on': True, 'category': 'task', 'description': '后台任务记录'},
    #             {'on': True, 'category': 'query_task', 'description': '读取任务当前执行状态及结果信息'},
    #             {'on': True, 'category': 'query', 'description': '查询操作'},
    #             {'on': True, 'category': 'search', 'description': '搜索操作'},
    #             {'on': True, 'category': 'statistics', 'description': '统计操作记录'},
    #             {'on': True, 'category': 'debug', 'description': '系统调试信息'},
    #             ]

    @staticmethod
    def _default_log_configs():
        return {
            'analysis': {
                'on': 1, 'alias': '分析日志', 'description': '固件代码分析操作日志'
            },
            'system_config': {
                'on': 1, 'alias': '系统配置日志', 'description': '系统配置参数操作日志'
            },
            'task': {
                'on': 1, 'alias': '任务运行日志', 'description': '后台任务运行信息日志'
            },
            'query_task': {
                'on': 1, 'alias': '任务查看日志', 'description': '后台任务信息查看操作日志'
            },
            'query': {
                'on': 1, 'alias': '业务查询日志', 'description': '系统业务数据查询日志'
            },
            'search': {
                'on': 1, 'alias': '数据搜索日志', 'description': '系统业务数据搜索日志'
            },
            'statistics': {
                'on': 1, 'alias': '统计日志', 'description': '系统数据统计操作日志'
            },
            'debug': {
                'on': 0, 'alias': '调试日志', 'description': '系统运行时调试信息日志'
            },
        }

    @staticmethod
    def _default_config():
        return {
            'log_configs': SystemConfig._default_log_configs()
        }

    @staticmethod
    def write_db(config):
        if config is None:
            config = SystemConfig._default_config()

        cfg_doc = {'key': 'sys_config', 'value': config}
        sys_dict_coll.update_one({'key': 'sys_config'},  {'$set': cfg_doc}, True)

    @staticmethod
    def read_db():
        if sys_dict_coll is None:
            cfg = SystemConfig._default_config()
        else:
            cfg_doc = sys_dict_coll.find({'key': 'sys_config'}, {'_id': 0, 'value': 1})
            cfg_list = list(cfg_doc)
            if len(cfg_list) == 0:
                cfg = SystemConfig._default_config()
            else:
                cfg = cfg_list[0]['value']
        return cfg

    @staticmethod
    def cache_load():
        # 从数据库中读取系统配置
        config = SystemConfig.read_db()

        # 将所有的系统配置参数写入缓存
        MyRedis.set('System_Config', config)
        # MyRedis.set('test', '111')
        return config

    @staticmethod
    def get_cache_log_cfg():
        # temp = MyRedis.get('test')
        # temp = MyRedis.get('test111')
        sys_config = MyRedis.get('System_Config')
        if sys_config is None:
            return []
        else:
            return sys_config['log_configs']

    # @staticmethod
    # def match_log_category(category):
    #     log_categories = SystemConfig.get_cache_log_cfg()
    #     cat_list = [item['category'] for item in log_categories]
    #     if category in cat_list:
    #         return True
    #     else:
    #         return False

    @staticmethod
    def is_log_on(category):
        log_configs = SystemConfig.get_cache_log_cfg()
        return log_configs[category]['on']
