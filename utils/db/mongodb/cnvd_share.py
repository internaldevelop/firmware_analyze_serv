import os
import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult

from utils.gadget.general import SysUtils

# 固件文件记录集合
cnvd_share_coll = utils.sys.config.g_cnvd_db_full["cnvd_share"]


class CnvdshareDO:

    @staticmethod
    def find(file_id):
        cursor = cnvd_share_coll.find({'file_id': file_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def search_info_of_component_name(name):
        cursor = cnvd_share_coll.find({'products.product': {'$regex': name}})
        return CursorResult.many(cursor)
