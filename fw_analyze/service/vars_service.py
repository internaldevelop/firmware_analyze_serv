from angr_helper.vars_recovery import VarsRecovery
from utils.db.mongodb.func_cache_dao import FuncCacheDAO


class VarsService:
    @staticmethod
    def extract_vars(file_id, func_addr):
        # 查找是否已有缓存结果，如有，不再做重复解析，直接返回缓存结果
        vars_dict = FuncCacheDAO.fetch_vars(file_id, func_addr)
        if vars_dict is not None:
            return {'memory_vars': vars_dict['memory_vars'], 'register_vars': vars_dict['register_vars']}

        # 解析恢复变量
        vr = VarsRecovery(file_id, func_addr)
        vars_dict = vr.vars()

        # 在数据库中缓存解析结果
        FuncCacheDAO.save_vars(file_id, func_addr, vars_dict)

        return vars_dict
