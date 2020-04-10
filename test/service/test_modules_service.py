import os

from utils.fs.fs_base import FsBase
from utils.gadget.my_file import MyFile
from utils.gadget.my_path import MyPath


class TestModulesService:
    @staticmethod
    def test_verify_file_type_and_write_file():
        file_id1 = '20514a76-74f8-4e73-b4d6-7aac73cf3998'
        file_id2 = '404c14ca-adb1-4010-bb09-3127be536c1a'
        file_path1 = os.path.join(MyPath.temporary(), file_id1)
        file_path2 = os.path.join(MyPath.temporary(), file_id2)
        file_write = os.path.join(MyPath.temporary(), '0000')

        for index in range(1, 5):
            data = MyFile.read(file_path1)
            MyFile.write(file_write, data)
            file_type, arch = FsBase.verify_exec_bin_file(file_write)
            print(str(file_type) + '\t\t' + str(arch))

            data = MyFile.read(file_path2)
            MyFile.write(file_write, data)
            file_type, arch = FsBase.verify_exec_bin_file(file_write)
            print(str(file_type) + '\t\t' + str(arch))
        pass
