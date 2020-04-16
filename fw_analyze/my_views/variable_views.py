from angr_helper.vars_recovery import VarsRecovery
from fw_analyze.service.vars_service import VarsService
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p


def analyze_extract_vars(request):
    file_id, func_addr = ReqParams.many(request, ['file_id', 'func_addr.hex'])

    vars_dict = VarsService.extract_vars(file_id, func_addr)

    return sys_app_ok_p(vars_dict)
