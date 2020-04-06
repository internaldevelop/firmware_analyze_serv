from utils.const.file_type import FileType
from utils.const.pack_type import PackType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_file import PackFileDO
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.gadget.strutil import StrUtils


class PackProcessService:
    """ 添加单个可执行文件，会产生一个虚拟固件包（没有包文件），用于该文件有可关联的固件包 """
    @staticmethod
    def add_single_exec(file_name, file_data):
        # 新的 pack ID
        pack_id = StrUtils.uuid_str()
        # 保存虚拟包记录
        PackFileDO.save(pack_id, '', name=file_name, pack_type=PackType.VIRTUAL, file_type=FileType.PACK)

        # 新的 pack 文件 UUID
        exec_file_id = StrUtils.uuid_str()
        # 保存文件记录
        FwFileDO.save_file_item(pack_id, exec_file_id, file_name, FileType.EXEC_FILE)

        # 在存储桶中保存文件数据
        # 保存文件内容
        FwFilesStorage.save(exec_file_id, file_name, file_name, FileType.EXEC_FILE, file_data)

        return pack_id, exec_file_id

    """ 移除固件包 """
    @staticmethod
    def remove_pack(pack_id):
        # 获取该固件包关联的所有文件 ID
        files_list = FwFileDO.get_files_of_pack(pack_id)
        file_id_list = [file_item['file_id'] for file_item in files_list]

        # 移除存储桶中，该固件包关联的所有文件
        FwFilesStorage.delete_many(file_id_list)

        # 移除存储桶中，固件包自身文件
        pack_item = PackFileDO.fetch_pack(pack_id)
        pack_file_id = pack_item['file_id']
        PackFilesStorage.delete(pack_file_id)

        # 移除该固件包关联的所有文件记录
        FwFileDO.delete_many_of_pack(pack_id)

        # 移除该固件包自身记录
        PackFileDO.delete(pack_id)

    @staticmethod
    def remove_all_packs():
        packs_list = PackFileDO.all_packs()
        pack_id_list = [pack_item['pack_id'] for pack_item in packs_list]
        for pack_id in pack_id_list:
            PackProcessService.remove_pack(pack_id)

    @staticmethod
    def remove_all_packs_by_type(pack_type):
        packs_list = PackFileDO.all_packs_type(pack_type)
        pack_id_list = [pack_item['pack_id'] for pack_item in packs_list]
        for pack_id in pack_id_list:
            PackProcessService.remove_pack(pack_id)
