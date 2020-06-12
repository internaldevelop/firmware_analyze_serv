import os


class MyPath:
    @staticmethod
    def work_root():
        return os.getcwd()

    @staticmethod
    def firmware():
        root_path = MyPath.work_root()
        return os.path.join(root_path, 'files', 'firmware')

    @staticmethod
    def component():
        root_path = MyPath.work_root()
        return os.path.join(root_path, 'files', 'source_code')

    @staticmethod
    def temporary():
        root_path = MyPath.work_root()
        return os.path.join(root_path, 'files', 'temporary')

    @staticmethod
    def samples():
        root_path = MyPath.work_root()
        return os.path.join(root_path, 'files', 'samples')
