import binwalk
import angr

from utils.const.file_type import FileType
from utils.gadget.file_type_scan.exec_file import ExecFile
from utils.gadget.file_type_scan.explicit_file import ExplicitFile
from utils.gadget.file_type_scan.office_file import OfficeFile


class FileTypeJudge:
    """ 返回文件类型，以及文件类型所对应的补充信息对象 """
    @staticmethod
    def scan_file_type(file_path, quiet=True):
        # 先做基础的文件扫描，识别出本系统定义的非可执行文件的文件类型
        file_type = FileTypeJudge._base_scan(file_path, quiet=quiet)
        if file_type != FileType.OTHER_FILE:
            return file_type, {}

        # 识别可执行文件
        is_exec, extra_props = ExecFile.is_exec_file(file_path, quiet=quiet)
        if is_exec:
            return FileType.EXEC_FILE, extra_props

        return FileType.OTHER_FILE, {}

    @staticmethod
    def _base_scan(file_path, quiet=True):
        # binwalk 扫描文件的签名
        bw_result = binwalk.scan(file_path, signature=True, opcodes=False, quiet=quiet)
        # bw_result = binwalk.scan('--signature', '--opcodes', file_path)

        # 签名结果为空，不是可执行二进制文件，文本文件或者是新建的 word 空文件
        sig_results = bw_result[0].results
        if len(sig_results) == 0:
            return FileType.NORMAL_FILE

        # 首先对签名做快速判定
        file_type = ExplicitFile.judge_type(sig_results)
        if file_type != FileType.OTHER_FILE:
            return file_type

        # 判断 Office 文件类型，Office 文件和 ZIP 文件有较大相似性，先做 office 判定
        file_type = OfficeFile.office_file(sig_results)
        if file_type != FileType.OTHER_FILE:
            return file_type
        # 检查是否为 zip 格式文件
        elif FileTypeJudge._is_zip_sig(sig_results):
            # 暂时把非 Office 文件设定为压缩文件
            return FileType.ZIP_FILE

        return FileType.OTHER_FILE

    @staticmethod
    def _is_zip_sig(sig_results):
        # 前n条：Zip archive data, at least v2.0 to extract, compressed size: 6051, uncompressed size: 21561, name: text.js
        # 最后一条 signature ，形如： 'End of Zip archive, footer length: 22'
        desc = sig_results[-1].description
        return desc.find('End of Zip archive') == 0

