import utils.sys.config
from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils
from utils.const.file_source import FileSource
from utils.const.file_type import FileType
from utils.const.pack_type import PackType


# 组件源码包集合
make_com_files_coll = utils.sys.config.g_firmware_db_full["component_make_files"]


class MakeCOMFileDO:

    # def __init__(self, pack_id=None):
    #     # pack_id 为None时表示新建的pack文件对象
    #     pass
    @staticmethod
    def search_component_name(name):
        cursor = make_com_files_coll.find({'file_name': name})
        return CursorResult.one(cursor)

    @staticmethod
    def search_files_of_pack(pack_id, file_type):
        cursor = make_com_files_coll.find({'pack_id': pack_id, 'file_type': file_type}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def save_file_item(pack_id, file_id, file_name, file_type, file_path='', extra_props=None):
        # 如果文件路径未给定，则使用文件名称代替
        if len(file_path) == 0:
            file_path = file_name

        doc = {'pack_id': pack_id, 'file_id': file_id, 'file_name': file_name, 'file_path': file_path,
               'file_type': file_type, 'create_time': SysUtils.get_now_time()}
        if extra_props is not None:
            doc['extra_props'] = extra_props

        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        rv = make_com_files_coll.update_one({'file_id': file_id, 'file_path': file_path}, {'$set': doc}, True)

    @staticmethod
    def save(pack_id, file_id, name=None, description='', pack_type=PackType.REAL,
             source_type=FileSource.REMOTE_DOWNLOAD, file_type=FileType.OTHER_FILE, source_addr=''):
        doc = {'pack_id': pack_id, 'file_id': file_id, 'name': name, 'description': description,
               'pack_type': pack_type, 'source_type': source_type, 'file_type': file_type, 'source_addr': source_addr,
               'create_time': SysUtils.get_now_time()}
        # 更新一条函数分析结果，如果没有旧记录，则创建一条新记录
        make_com_files_coll.update_one({'pack_id': pack_id}, {'$set': doc}, True)

    @staticmethod
    def fetch_pack(pack_id):
        cursor = make_com_files_coll.find({'pack_id': pack_id}, {'_id': 0})
        return CursorResult.one(cursor)

    @staticmethod
    def all_packs():
        cursor = make_com_files_coll.find({}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def all_packs_type(pack_type):
        cursor = make_com_files_coll.find({'pack_type': pack_type}, {'_id': 0})
        return CursorResult.many(cursor)

    @staticmethod
    def delete(pack_id):
        result = make_com_files_coll.delete_one({'pack_id': pack_id})
        return result.deleted_count == 1

    @staticmethod
    def delete_many(pack_id_list):
        for pack_id in pack_id_list:
            MakeCOMFileDO.delete(pack_id)
