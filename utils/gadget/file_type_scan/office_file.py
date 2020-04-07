from utils.const.file_type import FileType


class OfficeFile:
    @staticmethod
    def office_file(sig_results):
        if OfficeFile._has_office_feature(sig_results):
            # 检查是否 word 文件
            if OfficeFile._is_doc_sig(sig_results):
                return FileType.WORD_FILE

            # 检查是否 excel 文件
            if OfficeFile._is_excel_sig(sig_results):
                return FileType.EXCEL_FILE

            # 检查是否 PPT 文件
            if OfficeFile._is_ppt_sig(sig_results):
                return FileType.PPT_FILE

            # 以上 Office 文件都不是，判断是否其他 Office 文件
            return FileType.OTHER_OFFICE_FILE
        else:
            # 非 Office 文件
            return FileType.OTHER_FILE

    # 首条 signature ，形如： Zip archive data, at least v2.0 to extract, compressed size: 882,
    # uncompressed size: 13130, name: [Content_Types].xml
    # 最后一条 signature ，形如： 'End of Zip archive, footer length: 22'
    @staticmethod
    def _has_office_feature(sig_results):
        return sig_results[0].description.find('name: [Content_Types].xml') > 0 and \
               sig_results[-1].description.find('End of Zip archive') == 0

    @staticmethod
    def _has_office_tag(sig_results, app_tag):
        for sig in sig_results:
            desc = sig.description
            # 形如： 'Zip archive data, at least v2.0 to extract, compressed size: 488,
            # uncompressed size: 1365, name: word/fontTable.xml'
            if desc.find('Zip archive data') == 0 and desc.find(app_tag) > 0:
                return True
        return False

    @staticmethod
    def _is_doc_sig(sig_results):
        # 形如： 'Zip archive data, at least v2.0 to extract, compressed size: 488,
        # uncompressed size: 1365, name: word/fontTable.xml'
        return OfficeFile._has_office_tag(sig_results, 'name: word')

    @staticmethod
    def _is_excel_sig(sig_results):
        # 形如： 'Zip archive data, at least v2.0 to extract, compressed size: 512,
        # uncompressed size: 1001, name: xl/workbook.xml'
        return OfficeFile._has_office_tag(sig_results, 'name: xl/workbook')

    @staticmethod
    def _is_ppt_sig(sig_results):
        # 形如： 'Zip archive data, at least v2.0 to extract, compressed size: 811,
        # uncompressed size: 16863, name: ppt/diagrams/colors1.xml'
        return OfficeFile._has_office_tag(sig_results, 'name: ppt')
