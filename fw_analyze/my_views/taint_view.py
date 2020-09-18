from fw_analyze.service.cfg_analyze_service import CfgAnalyzeService
from fw_analyze.service.overflow_detect_service import OverflowDetectService
from fw_analyze.service.files_service import FilesService
from fw_analyze.service.functions_service import FunctionsService
from fw_analyze.service.vars_service import VarsService
from utils.db.mongodb.cfg_dao import CfgAnalyzeResultDAO
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.func_taint_dict_dao import TaintdictDO
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_ok_p_u, sys_app_err_p, sys_app_err
from utils.sys.error_code import Error
from angr_helper.function_parse import FunctionParse
from angr_helper.fw_vulner_analyze import FwVulnerAnalyze
from angr_helper.overflow_detect import Overflow_Detect
from angr_helper.angr_proj import AngrProj
import base64
from utils.gadget.strutil import StrUtils

from utils.task.my_task import MyTask

import utils.sys.config
# func_vulner_col = utils.sys.config.g_firmware_db_full["function_vulner_dict"]
# func_taint_col = utils.sys.config.g_firmware_db_full["function_taint_dict"]


def taintadd(request):
    # 从请求中取参数：文件 ID
    func_name, hazard, solution = ReqParams.many(request, ['func_name', 'hazard', 'solution'])

    # find func_name in taint_dict
    if TaintdictDO.search_func_name(func_name) is None:
        print("add func_name")
        # 新的 fun ID
        fun_id = StrUtils.uuid_str()
        TaintdictDO.save(fun_id, func_name, hazard, solution)

        # 保存操作日志
        LogRecords.save('', category='statistics', action='自定义污点函数－增加',
                        desc='污点函数（ID=%s）的信息，' % fun_id)
    else:
        print("already has func_name")

    return sys_app_ok_p([])


def taintdel(request):
    # 从请求中取参数：文件 ID
    func_name = ReqParams.one(request, 'func_name')
    TaintdictDO.delete(func_name)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='自定义污点函数－删除',
                    desc='污点函数（func_name=%s）的信息，' % func_name)

    return sys_app_ok_p([])


def taintmodify(request):
    # 从请求中取参数：文件 ID
    func_name, hazard, solution = ReqParams.many(request, ['func_name', 'hazard', 'solution'])

    TaintdictDO.update(func_name, hazard, solution)
    # 保存操作日志
    LogRecords.save('', category='statistics', action='自定义污点函数－删除',
                    desc='污点函数（func_name=%s）的信息，' % func_name)

    return sys_app_ok_p([])


def list(request):
    # 从请求中取参数：文件 ID
    # func_name, hazard, solution = ReqParams.many(request, ['func_name', 'hazard', 'solution'])
    taint_list = TaintdictDO.list()
    info_list = []
    for taint in taint_list:
        fun_id = taint.get('fun_id')
        func_name = taint.get('func_name')
        hazard = taint.get('hazard_desc')
        solution = taint.get('solution')
        doc = {'fun_id': fun_id, 'func_name': func_name, 'hazard': hazard, 'solution': solution}
        # doc = {'func_name': func_name, 'hazard': hazard, 'solution': solution}
        # doc = {'func_name': func_name}
        info_list.append(doc)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='查询所有定义污点函数',
                    desc='查询所有定义污点函数')

    return sys_app_ok_p_u(info_list)
    # return sys_app_ok_p({"taint": taint_list})


