import binwalk
import angr

from utils.const.file_type import FileType
from utils.gadget.file_type_scan.image_file import ImageFile
from utils.gadget.file_type_scan.office_file import OfficeFile
from utils.gadget.file_type_scan.pdf_file import PdfFile


class FileTypeJudge:
    @staticmethod
    def scan_file_type(file_path, quiet=True):
        # binwalk 扫描文件的签名
        bw_result = binwalk.scan(file_path, signature=True, opcodes=False, quiet=quiet)
        # bw_result = binwalk.scan('--signature', '--opcodes', file_path)

        # 签名结果为空，不是可执行二进制文件，文本文件或者是新建的 word 空文件
        sig_results = bw_result[0].results
        if len(sig_results) == 0:
            return FileType.NORMAL_FILE

        # 判断 Office 文件类型
        file_type = OfficeFile.office_file(sig_results)
        if file_type != FileType.OTHER_FILE:
            return file_type
        # 检查是否为 zip 格式文件
        elif FileTypeJudge._is_zip_sig(sig_results):
            # 暂时把非 Office 文件设定为压缩文件
            return FileType.ZIP_FILE

        # 检查是否为 pdf 格式文件
        file_type = PdfFile.pdf_file(sig_results)
        if file_type != FileType.OTHER_FILE:
            return file_type

        # 判断 图片 文件类型
        file_type = ImageFile.image_file(sig_results)
        if file_type != FileType.OTHER_FILE:
            return file_type

        return FileType.OTHER_FILE

    @staticmethod
    def _is_zip_sig(sig_results):
        # 最后一条 signature ，形如： 'End of Zip archive, footer length: 22'
        desc = sig_results[-1].description
        return desc.find('End of Zip archive') == 0

