from common.redis import MyRedis
import common.config


# 系统字典集合
sys_dict_coll = common.config.g_sys_dict_coll


class SystemConfig:
    @staticmethod
    def _default_log_categories():
        return [{'category': 'analysis', 'description': '文件解析操作'},
                {'category': 'system_config', 'description': '系统配置参数设置'},
                {'category': 'task', 'description': '后台任务记录'},
                {'category': 'query_task', 'description': '读取任务当前执行状态及结果信息'},
                {'category': 'query', 'description': '查询操作'},
                {'category': 'search', 'description': '搜索操作'},
                {'category': 'statistics', 'description': '统计操作记录'},
                {'category': 'debug', 'description': '系统调试信息'},
                ]

    @staticmethod
    def _default_config():
        return {
            'log_categories': SystemConfig._default_log_categories()
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
            return sys_config['log_categories']

    @staticmethod
    def match_log_category(category):
        log_categories = SystemConfig.get_cache_log_cfg()
        cat_list = [item['category'] for item in log_categories]
        if category in cat_list:
            return True
        else:
            return False
