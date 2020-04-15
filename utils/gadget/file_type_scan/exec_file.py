import angr
import binwalk

from utils.const.file_type import FileType

""" 
可执行文件，binwalk 检查指令集，并结合 angr BoyScout 判断指令集 arch
"""


class ExecFile:
    @staticmethod
    def is_exec_file(file_path, quiet=True):
        # binwalk 扫描文件的签名，并解析指令集
        bw_result = binwalk.scan(file_path, signature=True, opcodes=True, quiet=quiet)

        # 签名结果为空，不是可执行二进制文件，文本文件或者是新建的 word 空文件
        sig_results = bw_result[0].results
        if len(sig_results) == 0:
            return False, {}

        is_exec, ins_set = ExecFile._search_exec_feature(sig_results)
        if is_exec:
            return True, {'arch': ins_set, 'endianness': ''}

        return False, {}

    @staticmethod
    def _search_exec_feature(sig_results):
        check_list = [
            ['0', 'ELF, 64-bit LSB shared object, AMD x86-64', 'AMD64'],
            ['0', 'ELF, 64-bit LSB executable, AMD x86-64', 'AMD64'],
            ['0', 'Microsoft executable, portable (PE)', 'X86'],
            ['0', 'ELF, 32-bit LSB shared object, Intel 80386', 'X86'],
            ['0', 'ELF, 32-bit LSB MIPS64 shared object, MIPS', 'MIPS32'],
            ['0', 'ELF, 32-bit LSB executable, MIPS', 'MIPS32'],
            ['0', 'ELF, 32-bit LSB shared object, MIPS', 'MIPS32'],
            ['0', 'ELF, 32-bit LSB executable, ARM', 'ARM'],
            # ['n', 'MIPS instructions', 'MIPS32'],
            # ['n', 'MIPSEL instructions', 'MIPS32'],
        ]
        for check_item in check_list:
            if check_item[0] == '0' or check_item[0] == '-1':
                index = int(check_item[0])
                feature = check_item[1]
                if sig_results[index].description.find(feature) == 0:
                    return True, check_item[2]
            elif check_item[0] == 'n':
                feature = check_item[1]
                for sig in sig_results:
                    if sig.description.find(feature) == 0:
                        return True, check_item[2]

        return False, ''

    """ 
    对Windows DLL 和 SYS 文件，BoyScout 得出的结论是错误的，BoyScout 给出：
    "arch": "AMD64", "endianness": "Iend_LE"
    """
    @staticmethod
    def parse_exec_arch(file_path, prefer=None):
        if prefer is None:
            arch = 'ARM'
        else:
            arch = prefer['arch']

        try:
            proj = angr.Project(file_path, load_options={
                'main_opts': {
                    'backend': 'blob',
                    'base_addr': 0x10000,
                    'entry_point': 0x10000,
                    'arch': arch,
                    'offset': 0,
                }
            })
            boyscout = proj.analyses.BoyScout()
        except SystemError as sys_err:
            return '', ''
        except OSError as os_err:
            return '', ''

        return boyscout.arch, boyscout.endianness


