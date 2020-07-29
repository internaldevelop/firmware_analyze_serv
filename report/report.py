import os

from django.http import HttpResponse
from django.utils.http import urlquote
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Table, SimpleDocTemplate, Paragraph, Spacer

import utils.sys.config
from utils.gadget.general import SysUtils
from utils.gadget.strutil import StrUtils
from utils.http.response import sys_app_ok, sys_app_ok_p, sys_app_err

pack_files_col = utils.sys.config.g_firmware_db_full["pack_files"]
fw_files_col = utils.sys.config.g_firmware_db_full["fw_files"]
file_inverted_col = utils.sys.config.g_firmware_db_full["file_inverted_index"]
report_record_col = utils.sys.config.g_firmware_db_full["report_record"]

# 注册字体
pdfmetrics.registerFont(TTFont('SimSun', 'simsun.ttc'))


class Graphs:

    # def __init__(self):
    #     pass

    @staticmethod
    def text_type(font_size, leading, text_color, alignment):
        style = getSampleStyleSheet()
        ct = style['Normal']
        ct.fontName = 'SimSun'
        ct.fontSize = font_size

        # 设置行距
        if leading is not None:
            ct.leading = leading

        # 颜色
        if text_color is not None:
            ct.textColor = text_color

        # 居左:0  居中:1  居右:2
        if alignment is not None:
            ct.alignment = alignment
        return ct

    # 绘制标题
    @staticmethod
    def draw_con(content, title_name, ct):

        title = Paragraph(title_name, ct)
        content.append(title)

        # self = Graphs()
        # title_ct = self.text_type(18, 30, colors.black, 1)
        # # 添加标题并居中
        # title = Paragraph(title_name, title_ct)
        # content.append(title)

    # 绘制内容
    @staticmethod
    def draw_text(report_content, is_space):
        self = Graphs()

        ct = self.text_type(14, 25, colors.black, None)

        # 设置自动换行
        ct.wordWrap = 'CJK'

        if is_space == '1':
            # 第一行开头空格
            ct.firstLineIndent = 32

        text = Paragraph(report_content, ct)
        return text

    # 绘制表格
    @staticmethod
    def draw_table(data, col_width):

        style = [('FONTNAME', (0, 0), (-1, -1), 'SimSun'), # 字体
                 ('BACKGROUND', (0, 0), (-1, 0), '#d5dae6'), # 设置第一行背景颜色
                 ('ALIGN', (0, 0), (-1, -1), 'CENTER'), # 对齐
                 ('VALIGN', (-1, 0), (-2, 0), 'MIDDLE'), # 对齐
                 ('GRID', (0, 0), (-1, -1), 0.5, colors.grey) # 设置表格框线为grey色，线宽为0.5
            ]

        table = Table(data, colWidths=col_width, style=style)

        return table

    # 创建图表
    @staticmethod
    def draw_bar(bar_data=[], ax=[], items=[]):

        drawing = Drawing(600, 250)
        bc = VerticalBarChart()
        bc.x = 35
        bc.y = 100
        bc.height = 120
        bc.width = 350
        bc.data = bar_data
        bc.strokeColor = colors.black
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 100
        bc.valueAxis.valueStep = 10
        bc.categoryAxis.labels.dx = 8
        bc.categoryAxis.labels.dy = -10
        bc.categoryAxis.labels.angle = 20
        bc.categoryAxis.categoryNames = ax

        # 图示
        leg = Legend()

        leg.fontName = 'SimSun'
        leg.alignment = 'right'
        leg.boxAnchor = 'ne'

        leg.x = 505
        leg.y = 220

        leg.dxTextSpace = 10
        leg.columnMaximum = 4

        leg.colorNamePairs = items
        drawing.add(leg)
        drawing.add(bc)

        return drawing

    def save(self, pack_id):

        title_name = '固件分析报告'

        result_pack = pack_files_col.find({'pack_id': pack_id})

        pack_list = list(result_pack)

        firmware_name = ''
        firmware_file_num = 0
        fw_file_lists = ''

        if pack_list is not None or len(pack_list) > 0:
            pack_info = pack_list[0]
            firmware_name = pack_info.get('name')
            pack_id = pack_info.get('pack_id')

            result_files = fw_files_col.find({'pack_id': pack_id})
            fw_file_lists = list(result_files)
            if fw_file_lists is not None or len(fw_file_lists) > 0:
                firmware_file_num = len(fw_file_lists)

        # firmware_md5 = '721563f018a14723880d410778b749e3'
        # firmware_inst = 'MIPS'
        # firmware_size = '5.8M'
        # firmware_decomp_size = '7.2M'

        content = list()

        report_time = SysUtils.get_now_time_str();

        self.draw_con(content, title_name, self.text_type(20, 30, colors.black, 1))
        self.draw_con(content, '报告生成时间：' + report_time, self.text_type(11, 20, colors.black, 2))
        content.append(Spacer(300, 20))  # 添加空白，长度300，宽20

        content.append(self.draw_text('固件名称:' + firmware_name, '0'))
        # content.append(self.draw_text('固件 MD5:' + firmware_md5, '0'))
        # content.append(self.draw_text('指令集架构:' + firmware_inst, '0'))
        # content.append(self.draw_text('固件大小:' + firmware_size, '0'))
        # content.append(self.draw_text('固件解压包大小:' + firmware_decomp_size, '0'))
        content.append(self.draw_text('固件中共有' + str(firmware_file_num) + '个文件', '0'))

        content.append(Spacer(300, 10))    # 添加空白，长度300，宽10

        ct = self.text_type(10, 15, colors.black, None)
        # 设置自动换行
        ct.wordWrap = 'CJK'

        # 固件文件列表 start
        # 添加文档内容标题
        self.draw_con(content, '1 固件文件详情', self.text_type(18, 30, colors.black, 0))

        # 添加表格数据
        file_data = [('固件名称', '固件文件名称', '类型', '文件路径')]
        if fw_file_lists is not None or len(fw_file_lists) > 0:

            for file_info in fw_file_lists:

                pack_name_text = Paragraph(firmware_name, ct)
                file_name = file_info.get('file_name')
                file_name_text = Paragraph(file_name, ct)
                file_type = file_info.get('file_type')
                file_path = file_info.get('file_path')
                file_path_text = Paragraph(file_path, ct)

                row_data = (pack_name_text, file_name_text, file_type, file_path_text)
                file_data.append(row_data)

        file_col_width = [110, 110, 70, 160]

        content.append(self.draw_table(file_data, file_col_width))
        # 固件文件列表 end

        content.append(Spacer(300, 20))  # 添加空白，长度300，宽10

        # 敏感关键字列表 start
        # 添加文档内容标题
        self.draw_con(content, '2 敏感关键字', self.text_type(18, 30, colors.black, 0))

        lookup = {"from": "file_inverted_index", "localField": "file_id", "foreignField": "file_id", "as": "file_inverted"}

        match = {'pack_id': pack_id}

        result = fw_files_col.aggregate([{'$lookup': lookup}, {'$match': match}])

        item_list = list(result)

        # 添加表格数据
        data = [('文件名称', '关键字', '出现位置', '出现次数')]
        if item_list is not None and len(item_list) > 0:

            for file_keyword in item_list:
                file_inverted_list = file_keyword.get('file_inverted')

                if file_inverted_list is not None and len(file_inverted_list) > 0:
                    file_name = file_keyword.get('file_name')
                    file_name_text = Paragraph(file_name, ct)

                    for file_inverted_info in file_inverted_list:
                        index_con = file_inverted_info.get('index_con')
                        index_con_text = Paragraph(index_con, ct)
                        position = file_inverted_info.get('position')
                        appear_total = file_inverted_info.get('appear_total')

                        row_data = (file_name_text, index_con_text, position, appear_total)
                        data.append(row_data)

        col_width = [120, 240, 45, 45]

        content.append(self.draw_table(data, col_width))
        # 敏感关键字列表 end

        content.append(Spacer(300, 20))  # 添加空白，长度300，宽10
        self.draw_con(content, '报告结束', self.text_type(11, 20, colors.black, 1))

        pdf_name = firmware_name + title_name + '.pdf'

        path = './firmware_analyze_serv_report/'

        if not os.path.exists(path):
            os.mkdir(path)

        pdf_path = path + pdf_name
        # 生成pdf文件
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        doc.build(content)

        report_id = StrUtils.uuid_str()
        report_record_info = {'report_id': report_id, 'pack_id': pack_id, 'pack_name': firmware_name, 'pdf_path': pdf_path, 'pdf_name': pdf_name, 'create_time': report_time}

        report_record_col.save(report_record_info)

        return sys_app_ok()

    # 报告列表查询
    def get_report_pdf(self, report_id, pack_id, pack_name, pdf_name):
        query_condition = {}

        if report_id is not None and len(report_id) > 0:
            query_condition['report_id'] = report_id
        if pack_id is not None and len(pack_id) > 0:
            query_condition['pack_id'] = pack_id
        if pack_name is not None and len(pack_name) > 0:
            query_condition['pack_name'] = {'$regex': pack_name}
        if pdf_name is not None and len(pdf_name) > 0:
            query_condition['pdf_name'] = {'$regex': pdf_name}

        result = report_record_col.find(query_condition).sort('_id', -1)
        item_list = list(result)

        if item_list is not None and len(item_list) > 0:

            for item in item_list:
                item.pop('_id')
            return sys_app_ok_p(item_list)
        return sys_app_ok()

    def download_report(self, report_id):

        report_info = report_record_col.find_one({'report_id': report_id})
        if report_info is None:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        store_path = report_info.get('pdf_path')
        pdf_name = report_info.get('pdf_name')

        def send_chunk():  # 流式读取
            with open(store_path, 'rb') as target_file:
                while True:
                    chunk = target_file.read(20 * 1024 * 1024)  # 每次读取20M
                    if not chunk:
                        break
                    yield chunk

        # 设置响应内容的文件下载参数
        response = HttpResponse(send_chunk(), content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment;filename="%s"' % (urlquote(pdf_name))
        return response

