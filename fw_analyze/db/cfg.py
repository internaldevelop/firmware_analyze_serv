import utils.sys.config
from utils.gadget.general import SysUtils

# firmware 信息集合
cfg_result_col = utils.sys.config.g_cfg_result_coll


class CfgAnalyzeResult:

    @staticmethod
    def save(file_id, task_id, cfg_result):
        doc = {'file_id': file_id, 'task_id': task_id, 'cfg_result': cfg_result, 'create_time': SysUtils.get_now_time()}
        # 更新一条 cfg 分析结果，如果没有旧记录，则创建一条新记录
        cfg_result_col.update_one({'file_id': file_id}, {'$set': doc}, True)

    @staticmethod
    def find(file_id):
        doc = cfg_result_col.find({'file_id': file_id}, {'_id': 0})
        if doc is not None:
            result = list(doc)[0]
            return result['task_id'], result['cfg_result']
        else:
            return None, None
