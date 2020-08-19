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
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.pack_files_storage import PackFilesStorage
from utils.gadget.general import SysUtils
from utils.gadget.strutil import StrUtils
from utils.http.response import sys_app_ok, sys_app_ok_p, sys_app_err
from utils.gadget.my_path import MyPath

pack_files_col = utils.sys.config.g_firmware_db_full["pack_files"]
fw_files_col = utils.sys.config.g_firmware_db_full["fw_files"]
file_inverted_col = utils.sys.config.g_firmware_db_full["file_inverted_index"]
report_record_col = utils.sys.config.g_firmware_db_full["report_record"]
component_files_col = utils.sys.config.g_firmware_db_full["component_files"]

# 注册字体
# pdfmetrics.registerFont(TTFont('SimSun', 'simsun.ttc'))
path_font = MyPath.work_root() + '/report/simsun.ttc'
pdfmetrics.registerFont(TTFont('SimSun', path_font))

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
        execute_file_num = 0
        fw_file_lists = ''

        firmware_md5 = ''
        firmware_size = ''

        if pack_list is not None and len(pack_list) > 0:
            pack_info = pack_list[0]
            firmware_name = pack_info.get('name')
            pack_id = pack_info.get('pack_id')
            pack_file_id = pack_info.get('file_id')

            result_files = fw_files_col.find({'pack_id': pack_id})
            fw_file_lists = list(result_files)
            if fw_file_lists is not None or len(fw_file_lists) > 0:
                firmware_file_num = len(fw_file_lists)

                for file_info in fw_file_lists:
                    fw_file_type = file_info.get('file_type')

                    if fw_file_type == 4:
                        execute_file_num += 1

            item = PackFilesStorage.fetch(pack_file_id)

            firmware_md5 = item.get('md5')
            length_b = item.get('length')
            length_kb = length_b / 1024
            length_mb = length_kb / 1024
            if length_kb < 1:
                firmware_size = str('%.2f' % length_b) + ' B'
            elif length_mb < 1:
                firmware_size = str('%.2f' % length_kb) + ' KB'
            else:
                firmware_size = str('%.2f' % length_mb) + ' MB'
        else:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        # firmware_inst = 'MIPS'
        # firmware_decomp_size = '7.2M'

        content = list()

        report_time = SysUtils.get_now_time_str();

        self.draw_con(content, title_name, self.text_type(20, 30, colors.black, 1))
        self.draw_con(content, '报告生成时间：' + report_time, self.text_type(11, 20, colors.black, 2))
        content.append(Spacer(300, 20))  # 添加空白，长度300，宽20

        self.draw_con(content, '1 固件分析综述', self.text_type(18, 30, colors.black, 0))

        content.append(self.draw_text('固件名称:' + firmware_name, '0'))
        if len(firmware_md5) > 0:
            content.append(self.draw_text('固件 MD5:' + firmware_md5, '0'))

        if len(firmware_size) > 0:
            content.append(self.draw_text('固件大小:' + firmware_size, '0'))
        # content.append(self.draw_text('指令集架构:' + firmware_inst, '0'))
        # content.append(self.draw_text('固件解压包大小:' + firmware_decomp_size, '0'))
        content.append(self.draw_text('固件中共有' + str(firmware_file_num) + '个文件', '0'))
        content.append(self.draw_text('固件中共有' + str(execute_file_num) + '个可执行文件', '0'))

        content.append(Spacer(300, 10))    # 添加空白，长度300，宽10

        ct = self.text_type(10, 15, colors.black, 1)
        # 设置自动换行
        ct.wordWrap = 'CJK'

        # 关联的漏洞 start
        # 添加文档内容标题
        self.draw_con(content, '2 组件关联的漏洞', self.text_type(18, 30, colors.black, 0))

        # 添加表格数据
        edb_data = [('序号', '固件名称', '固件文件名称', '组件文件名称', '相似度', '组件版本', '漏洞编号')]

        if fw_file_lists is not None and len(fw_file_lists) > 0:
            pack_name_text = Paragraph(firmware_name, ct)
            num = 1

            for file_info in fw_file_lists:
                fw_file_name = file_info.get('file_name')
                fw_file_name_text = Paragraph(fw_file_name, ct)
                extra_props = file_info.get('extra_props')

                if extra_props is not None:
                    extra_props.setdefault('name', '')
                    extra_props.setdefault('version', '')
                    extra_props.setdefault('edb_id', '')
                    extra_props.setdefault('similarity', '')

                    file_name = extra_props['name']
                    version = extra_props['version']
                    edb_id = extra_props['edb_id']
                    similarity = extra_props['similarity']

                    if len(file_name) > 0 or len(version) > 0 or len(edb_id) > 0:
                        file_name_text = Paragraph(file_name, ct)
                        row_data = (num, pack_name_text, fw_file_name_text, file_name_text, str(similarity), version, edb_id)
                        num += 1
                        edb_data.append(row_data)

        col_width = [30, 100, 70, 70, 40, 60, 90]

        content.append(self.draw_table(edb_data, col_width))

        if len(edb_data) < 2:
            self.draw_con(content, '组件未关联漏洞', self.text_type(11, 20, colors.black, 1))
        # 关联的漏洞 end

        content.append(Spacer(300, 20))  # 添加空白，长度300，宽10

        # 固件文件列表 start
        # 添加文档内容标题
        self.draw_con(content, '3 可执行文件详情', self.text_type(18, 30, colors.black, 0))

        # 添加表格数据
        file_data = [('序号', '固件文件名称', '大小', 'MD5值', '文件路径')]
        if fw_file_lists is not None and len(fw_file_lists) > 0:

            num = 1

            for file_info in fw_file_lists:

                file_name = file_info.get('file_name')
                file_name_text = Paragraph(file_name, ct)
                # file_type = file_info.get('file_type')
                file_path = file_info.get('file_path')
                file_path_text = Paragraph(file_path, ct)
                fw_file_type = file_info.get('file_type')

                file_id = file_info.get('file_id')

                item = FwFilesStorage.fetch(file_id)

                fw_file_md5 = item.get('md5')
                fw_file_md5_text = Paragraph(fw_file_md5, ct)
                length_b = item.get('length')
                length_kb = length_b / 1024
                length_mb = length_kb / 1024
                if length_kb < 1:
                    fw_file_size = str('%.2f' % length_b) + ' B'
                elif length_mb < 1:
                    fw_file_size = str('%.2f' % length_kb) + ' KB'
                else:
                    fw_file_size = str('%.2f' % length_mb) + ' MB'

                if fw_file_type == 4:
                    row_data = (num, file_name_text, fw_file_size, fw_file_md5_text, file_path_text)
                    num += 1
                    file_data.append(row_data)

        file_col_width = [30, 100, 50, 120, 160]

        content.append(self.draw_table(file_data, file_col_width))
        # 固件文件列表 end

        content.append(Spacer(300, 20))  # 添加空白，长度300，宽10

        # 敏感关键字列表 start
        # 添加文档内容标题
        self.draw_con(content, '4 特征码', self.text_type(18, 30, colors.black, 0))

        child_num = 1
        for fw_file_info in fw_file_lists:
            file_id = fw_file_info.get('file_id')
            file_name = fw_file_info.get('file_name')

            result = file_inverted_col.find({'file_id': file_id}).sort('appear_total', -1)
            item_list = list(result)
            if item_list is not None and len(item_list) > 0:

                # 添加文档内容标题
                self.draw_con(content, ' (' + str(child_num) + ')' + file_name + '文件特征码', self.text_type(15, 30, colors.black, 0))

                child_num += 1

                # 添加表格数据
                data = [('序号', '关键字', '出现位置', '出现次数')]

                num = 1
                for file_inverted_info in item_list:

                    appear_total = file_inverted_info.get('appear_total')
                    if num < 11 and appear_total > 1:
                        index_con = file_inverted_info.get('index_con')
                        if len(index_con) < 10 or len(index_con) > 50:
                            continue
                        index_con_text = Paragraph(index_con, ct)
                        position = file_inverted_info.get('position')
                        position_str = ''  # 出现位置

                        con_list = position.split(',')
                        for con_index in range(len(con_list)):
                            con_info = con_list[con_index]

                            position_hex = hex(int(con_info))
                            position_str += str(position_hex) + ' '

                            if con_index > 27:
                                position_str += '... '
                                break

                        position_text = Paragraph(position_str, ct)

                        row_data = (num, index_con_text, position_text, appear_total)
                        data.append(row_data)
                        num += 1

                col_width = [30, 180, 190, 50]

                content.append(self.draw_table(data, col_width))

        if child_num == 1:
            self.draw_con(content, '组件文件未生成特征码', self.text_type(11, 20, colors.black, 1))
        # 敏感关键字列表 end

        content.append(Spacer(300, 10))  # 添加空白，长度300，宽10

        self.draw_con(content, '报告结束', self.text_type(11, 20, colors.black, 1))

        time_stamp = SysUtils.parse_time_stamp_str()
        inde = firmware_name.index('.')

        if inde > -1:
            firmware_name = firmware_name[0: inde]

        pdf_name = firmware_name + title_name + time_stamp + '.pdf'

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

