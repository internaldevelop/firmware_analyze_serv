from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.http.response import sys_app_ok_p, sys_app_err
from utils.http.request import ReqParams
from angr_helper.angr_proj import AngrProj
import zipfile
from PySquashfsImage import SquashFsImage


def system_info(request):
    return sys_app_ok_p({'service_name': 'fw_analyze',
                         'run_status': '运行状况良好',
                         'description': '嵌入式固件分析检测系统，支持固件上传下载，支持架构、文件系统识别提取，' +
                                        '支持汇编代码和中间代码的转换，可进行函数级分析、变量级分析，支持数据结构恢复，' +
                                        '并可检测常见的代码缺陷漏洞。',
                         'version': '1.0.0.1',
                         'copyright': '中国电力科学研究院 2020'
                         })


def check_file(request):
    file_id = ReqParams.one(request, 'file_id')
    file_path = FwFilesStorage.export(file_id)

    if file_path is None:
        return sys_app_err('FW_FILE_NOT_FOUND')

    return sys_app_ok_p({'file_id': file_id, 'file_path': file_path})
