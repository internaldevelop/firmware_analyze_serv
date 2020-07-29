from report.report import Graphs
from utils.http.http_request import req_get_param, req_post_param
from utils.http.request import ReqParams

report = Graphs()


# 报告生成
def create_report(request):
    # 获取参数
    pack_id = req_get_param(request, 'pack_id')
    return report.save(pack_id)


# 报告列表查询
def get_report_pdf(request):
    # 获取参数
    report_id, pack_id, pack_name, pdf_name = ReqParams.many(request, ['report_id', 'pack_id', 'pack_name', 'pdf_name'])
    return report.get_report_pdf(report_id, pack_id, pack_name, pdf_name)


# 报告下载
def download_report(request):
    # 获取参数
    report_id = req_get_param(request, 'report_id')
    return report.download_report(report_id)

