import os


class MyFile:
    @staticmethod
    def read(file_path, read_len=0):
        with open(file_path, 'rb') as file:
            if read_len == 0:
                contents = file.read()
            else:
                contents = file.read(read_len)
        return contents

    @staticmethod
    def exist(file_path, folder=None):
        if folder is not None:
            file_path = os.path.join(folder, file_path)
        return os.path.exists(file_path)

