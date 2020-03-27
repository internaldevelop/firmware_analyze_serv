from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err


def system_info(request):
    return sys_app_ok_p({'service_name': 'fw_analyze',
                         'run_status': '运行状况良好',
                         'description': '嵌入式固件分析检测系统，支持固件上传下载，支持架构、文件系统识别提取，' +
                                        '支持汇编代码和中间代码的转换，可进行函数级分析、变量级分析，支持数据结构恢复，' +
                                        '并可检测常见的代码缺陷漏洞。',
                         'version': '1.0.0.1',
                         'copyright': '中国电力科学研究院 2020'
                         })
