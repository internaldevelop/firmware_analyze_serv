import common.config

import re
import os
from common.utils.general import SysUtils

# firmware 信息集合
cfg_result_col = common.config.g_cfg_result_col


class CfgAnalyzeResult:

    @staticmethod
    def save(file_id, task_id, cfg_result):
        doc = {'file_id': file_id, 'task_id': task_id, 'cfg_result': cfg_result, 'create_time': SysUtils.get_now_time()}
        cfg_result_col.insert_one(doc)

    @staticmethod
    def find(file_id):
        doc = cfg_result_col.find({'file_id': file_id}, {'_id': 0})
        if doc is not None:
            result = list(doc)[0]
            return result['task_id'], result['cfg_result']
        else:
            return None, None
