import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils
from utils.const.file_source import FileSource
from utils.const.file_type import FileType
from utils.const.pack_type import PackType


# 组件源码包集合
pack_com_files_coll = utils.sys.config.g_firmware_db_full["component_files"]


class PackCOMFileDO:

    # def __init__(self, pack_id=None):
    #     # pack_id 为None时表示新建的pack文件对象
    #     pass
    @staticmethod
    def save(pack_id, file_id, edb_id, title, version, path_file_name, name=None, description='', pack_type=PackType.REAL,
             source_type=FileSource.REMOTE_DOWNLOAD, file_type=FileType.OTHER_FILE, source_addr=''):
        doc = {'pack_id': pack_id, 'file_id': file_id, 'edb_id': edb_id, 'title': title, 'version': version, 'compile': 0, 'name': name, 'file_path': path_file_name, 'description': description,
               'pack_type': pack_type, 'source_type': source_type, 'file_type': file_type, 'source_addr': source_addr,
               'create_time': SysUtils.get_now_time()}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        pack_com_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def set_compile_flag(pack_id, flag='success'):# None ,success, failed
        doc = {'compile': flag}
        # 更新记录
        rv = pack_com_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def fetch_pack(pack_id):
        cursor = pack_com_files_coll.find({'pack_id': pack_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def all_packs():
        cursor = pack_com_files_coll.find({}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def all_packs_type(pack_type):
        cursor = pack_com_files_coll.find({'pack_type': pack_type}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def delete(pack_id):
        result = pack_com_files_coll.delete_one({'pack_id': pack_id})
        return result.deleted_count == 1

    @staticmethod
    def delete_many(pack_id_list):
        for pack_id in pack_id_list:
            PackCOMFileDO.delete(pack_id)
