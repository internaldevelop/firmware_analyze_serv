from angr_helper.angr_proj import AngrProj
from angr_helper.function_parse import FunctionParse
from angr_helper.fw_entry_state import FwEntryState
from utils.db.mongodb.file_cache_dao import FileCacheDAO


class FilesService:

    @staticmethod
    def bin_state_info(file_id):
        # 查找是否已有缓存结果，如有，不再做重复解析，直接返回缓存结果
        state_dict = FileCacheDAO.fetch_state_info(file_id)
        if state_dict is not None:
            return state_dict

        # 通过 project 快速解析文件
        angr_proj = AngrProj(file_id)

        # 从 project 中取 entry 对象
        entry_state = FwEntryState(angr_proj)

        # 读取状态机信息
        state_dict = entry_state.entry_info()

        # 在数据库中缓存解析结果
        FileCacheDAO.save_state_info(file_id, state_dict)

        return state_dict

    @staticmethod
    def functions_list(file_id):
        # 查找是否已有缓存结果，如有，不再做重复解析，直接返回缓存结果
        funcs_list = FileCacheDAO.fetch_functions(file_id)
        if funcs_list is not None:
            return funcs_list
        else:
            return []

        # # 通过 project 快速解析文件
        # angr_proj = AngrProj(file_id)
        # funcs_list = FunctionParse.functions_extract(angr_proj.proj)

        # 在数据库中缓存解析结果
        # FileCacheDAO.save_functions(file_id, funcs_list)

        # return funcs_list
