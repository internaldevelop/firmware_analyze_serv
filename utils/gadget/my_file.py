import os


class MyFile:
    @staticmethod
    def _join_file_path(file_path, folder=None):
        if folder is not None:
            return os.path.join(folder, file_path)
        else:
            return file_path

    @staticmethod
    def read(file_path, folder=None, read_len=0):
        file_path = MyFile._join_file_path(file_path, folder)
        try:
            with open(file_path, 'rb') as file:
                if read_len == 0:
                    contents = file.read()
                else:
                    contents = file.read(read_len)
        except IOError as io_err:
            return None

        return contents

    @staticmethod
    def write(file_path, bin_data, folder=None):
        file_path = MyFile._join_file_path(file_path, folder)
        try:
            with open(file_path, 'wb') as file:
                file.write(bin_data)
        except IOError as io_err:
            return None

        return file_path

    @staticmethod
    def exist(file_path, folder=None):
        return os.path.exists(MyFile._join_file_path(file_path, folder))

    # 返回 folders_list 和 file_name
    @staticmethod
    def file_path_to_folder_list(file_path):
        # 判断文件路径的分隔符
        delimiter = '\\' if file_path.find('\\') >= 0 else '/'

        # 移除收尾的分隔符
        file_path = file_path.strip(delimiter)

        # 空串，folders_list 和 file_name 都为空
        if len(file_path) == 0:
            return [], ''
        # elif file_path.find(delimiter) < 0:
        #     # 非空串，但找不到分隔符，则当前 file_path 即为 file_name
        #     return [], file_path

        # 分隔字符串成字符串列表
        folders_list = file_path.split(delimiter)
        # 列表最后一个元素为 file_name，剩余的留作 folders_list
        file_name = folders_list[-1]
        folders_list.pop()
        return folders_list, file_name

