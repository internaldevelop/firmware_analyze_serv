import zipfile
import patoolib
import py7zr

from utils.db.mongodb.fw_file import FwFile
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p, sys_app_err


def test_zip_file(request):
    file_id = ReqParams.one(request, 'file_id')

    file_path, file_arch = FwFile.id_to_file(file_id)

    # compress_files = _test_zipfile(file_path)

    # compress_files = _test_patool(file_path)

    compress_files = _test_py7zr(file_path)

    return sys_app_ok_p(compress_files)


def _test_zipfile(file_path):
    # 参考链接
    # https://www.cnblogs.com/gufengchen/archive/2019/05/31/10956009.html
    # https://docs.python.org/3/library/zipfile.html
    if not zipfile.is_zipfile(file_path):
        return 'ZIP_FORMAT_UNKNOWN'

    zip_file = zipfile.ZipFile(file_path, 'r')
    # for file in zip_file.namelist():
    #     print(file)
    compress_files = []
    for info in zip_file.infolist():
        print(info.filename, info.file_size, info.header_offset)
        compress_files.append(str(info))

    # 实例一定要 close
    zip_file.close()

    return compress_files


def _test_patool(file_path):
    archive_format = patoolib.get_archive_format(file_path)
    rv = patoolib.test_archive(file_path)

    contents = patoolib.list_archive(file_path)
    return contents


def _test_py7zr(file_path):
    zip_file = py7zr.SevenZipFile(file_path)
    test_result = zip_file.test()
    info = zip_file.archiveinfo()
    contents = zip_file.list()
    zip_file.close()
    return contents
