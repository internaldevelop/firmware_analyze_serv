from angr_helper.function_parse import FunctionParse
from utils.db.mongodb.func_cache_dao import FuncCacheDAO


class FunctionsService:
    @staticmethod
    def func_props(file_id, func_addr):
        # 查找是否已有缓存结果，如有，不再做重复解析，直接返回缓存结果
        props_dict = FuncCacheDAO.fetch_props(file_id, func_addr)
        if props_dict is not None:
            return props_dict

        # 加载、解析，获得函数属性
        func_parse = FunctionParse(file_id, func_addr)
        props_dict = func_parse.get_props()

        # 在数据库中缓存解析结果
        FuncCacheDAO.save_props(file_id, func_addr, props_dict)

        return props_dict

