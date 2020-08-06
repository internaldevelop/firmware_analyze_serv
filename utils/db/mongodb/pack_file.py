import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils
from utils.const.file_source import FileSource
from utils.const.file_type import FileType
from utils.const.pack_type import PackType


# 固件包记录集合
pack_files_coll = utils.sys.config.g_firmware_db_full["pack_files"]


class PackFileDO:

    # def __init__(self, pack_id=None):
    #     # pack_id 为None时表示新建的pack文件对象
    #     pass

    @staticmethod
    def save(pack_id, file_id, name=None, description='', pack_type=PackType.REAL,
             source_type=FileSource.REMOTE_DOWNLOAD, file_type=FileType.OTHER_FILE, source_addr=''):
        doc = {'pack_id': pack_id, 'file_id': file_id, 'name': name, 'description': description,
               'pack_type': pack_type, 'source_type': source_type, 'file_type': file_type, 'source_addr': source_addr,
               'create_time': SysUtils.get_now_time()}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        pack_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def save_manufacturer(pack_id, manufacturer, model):
        doc = {'pack_id': pack_id, 'manufacturer': manufacturer, 'model': model}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        pack_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def savefs(pack_id, filesystem, arch=None):
        doc = {'filesystem': filesystem, 'arch': arch}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        pack_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def updateArch(pack_id, arch):
        doc = {'arch': arch}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        pack_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)


    @staticmethod
    def fetch_pack(pack_id):
        cursor = pack_files_coll.find({'pack_id': pack_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def all_packs():
        cursor = pack_files_coll.find({}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def all_packs_type(pack_type):
        cursor = pack_files_coll.find({'pack_type': pack_type}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def delete(pack_id):
        result = pack_files_coll.delete_one({'pack_id': pack_id})
        return result.deleted_count == 1

    @staticmethod
    def delete_many(pack_id_list):
        for pack_id in pack_id_list:
            PackFileDO.delete(pack_id)
