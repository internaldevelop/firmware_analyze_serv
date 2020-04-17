from fw_analyze.service.files_service import FilesService
from utils.http.http_request import req_get_param
from utils.http.response import sys_app_ok_p
from angr_helper.angr_proj import AngrProj
from angr_helper.fw_entry_state import FwEntryState
from utils.db.mongodb.logs import LogRecords


def entry_state_info(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    info = FilesService.bin_state_info(file_id)

    # 保存操作日志
    LogRecords.save(info, category='analysis', action='入口状态机',
                    desc='分析可执行文件的入口状态机参数')

    return sys_app_ok_p(info)
