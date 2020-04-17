import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils

# CFG 分析结果集合
cfg_result_col = utils.sys.config.g_firmware_db_full["cfg_result"]


class CfgAnalyzeResultDAO:

    @staticmethod
    def save(file_id, task_id, cfg_result):
        doc = {'file_id': file_id, 'task_id': task_id, 'create_time': SysUtils.get_now_time()}
        doc = dict(doc, **cfg_result)
        # 更新一条 cfg 分析结果，如果没有旧记录，则创建一条新记录
        cfg_result_col.update_one({'file_id': file_id}, {'$set': doc}, True)

    @staticmethod
    def find(file_id):
        cursor = cfg_result_col.find({'file_id': file_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def get_functions(file_id):
        result = CfgAnalyzeResultDAO.find(file_id)
        if result is None:
            return []
        return result['functions']
