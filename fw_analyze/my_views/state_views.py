from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from angr_helper.angr_proj import AngrProj
from angr_helper.fw_entry_state import FwEntryState


def entry_state_info(request):
    # 从请求中取参数：文件 ID
    file_id = req_get_param(request, 'file_id')

    # 通过 project 快速解析文件
    angr_proj = AngrProj(file_id)

    # 从 project 中取 entry 对象
    entry_state = FwEntryState(angr_proj)

    # 读取状态机信息
    info = entry_state.entry_info()

    return sys_app_ok_p(info)
