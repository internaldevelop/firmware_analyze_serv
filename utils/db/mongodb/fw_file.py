import os


class FwFile:

    @staticmethod
    def id_to_file(file_id):
        return FwFile._simulate_id_to_file(file_id)

    @staticmethod
    def _simulate_id_to_file(file_id):
        # 临时用指定文件测试
        root_path = os.getcwd()
        # root_path = os.get_exec_path()
        # root_path = os.path.dirname(os.path.realpath(__file__))
        # root_path = os.path.dirname(root_path)
        samples_path = os.path.join(root_path, 'readme', 'studyAndTest', 'angr', 'samples')
        file_list = {
            # 自动检测结果 arch 为 'AMD64'
            '1': {'file_name': 'ais3_crackme', 'file_arch': ''},
            # 自动检测结果 arch 为 'X86'
            '2': {'file_name': '1.6.26-libjsound.so', 'file_arch': ''},
            # 自动检测结果 arch 为 'AMD64'
            '3': {'file_name': 'mysql', 'file_arch': ''},
            '4': {'file_name': 'samples.zip', 'file_arch': ''},
            '5': {'file_name': 'samples.7z', 'file_arch': ''},
            '11': {'file_name': '2E0', 'file_arch': 'MIPS32'},
            '12': {'file_name': 'libstdc++.so.6.0.16', 'file_arch': ''},
            '13': {'file_name': '2E0.7z', 'file_arch': 'MIPS32'},
            '14': {'file_name': 'libm-0.9.33.2.so', 'file_arch': ''},
            '15': {'file_name': '1702A0.squashfs', 'file_arch': ''},
            '21': {'file_name': 'opkg', 'file_arch': ''},
        }
        if file_id not in file_list:
            file_name = 'ais3_crackme'
            file_arch = ''
        else:
            file_name = file_list[file_id]['file_name']
            file_arch = file_list[file_id]['file_arch']
        return os.path.join(samples_path, file_name), file_arch
