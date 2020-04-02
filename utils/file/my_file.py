
class MyFile:
    @staticmethod
    def read(file_path, read_len=0):
        with open(file_path, 'rb') as file:
            if read_len == 0:
                contents = file.read()
            else:
                contents = file.read(read_len)
        return contents

