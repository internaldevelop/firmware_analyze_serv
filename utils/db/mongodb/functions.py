import utils.sys.config
from utils.gadget.general import SysUtils

# firmware 信息集合
func_result_col = utils.sys.config.g_func_result_coll


class FunctionsResult:
    @staticmethod
    def save(file_id, task_id, func_result):
        doc = {'file_id': file_id, 'task_id': task_id, 'func_result': func_result, 'create_time': SysUtils.get_now_time()}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        func_result_col.update_one({'file_id': file_id}, {'$set': doc}, True)

    @staticmethod
    def find(file_id):
        doc = func_result_col.find({'file_id': file_id}, {'_id': 0})
        if doc is not None:
            records = list(doc)
            if len(records) == 0:
                return None, None

            result = records[0]
            return result['task_id'], result['func_result']
        else:
            return None, None
