from utils.http.response import sys_app_ok_p
from utils.http.request import ReqParams
from angr_helper.angr_proj import AngrProj
import zipfile
from PySquashfsImage import SquashFsImage


def system_info(request):
    return sys_app_ok_p({'service_name': 'fw_analyze',
                         'run_status': '运行状况良好',
                         'description': '嵌入式固件分析检测系统，支持固件上传下载，支持架构、文件系统识别提取，' +
                                        '支持汇编代码和中间代码的转换，可进行函数级分析、变量级分析，支持数据结构恢复，' +
                                        '并可检测常见的代码缺陷漏洞。',
                         'version': '1.0.0.1',
                         'copyright': '中国电力科学研究院 2020'
                         })


def _test_zip_file(file_path):
    # https://www.cnblogs.com/gufengchen/archive/2019/05/31/10956009.html
    if not zipfile.is_zipfile(file_path):
        return

    z = zipfile.ZipFile(file_path, 'r')
    for file in z.namelist():
        print(file)
    for info in z.infolist():
        print(info.file_size, info.header_offset)


def _test_squash_fs_file(file_path):
    # https://github.com/matteomattei/PySquashfsImage
    image = SquashFsImage(file_path)
    for i in image.root.findAll():
        if i.getName() == b'rp-pppoe.so':
            content = i.getContent()
            print(i.getName())
        print(i.getName())
    image.close()
    # image = SquashFsImage(file_path)
    # for i in image.root.findAllPaths():
    #     print(i)
    # image.close()


def _test_jffs2_fs_file(file_path):
    # https://gist.github.com/geekman/a0692e912a6e76a777bc
    # https://github.com/sviehb/jefferson
    return


def check_file(request):
    file_id = ReqParams.one(request, 'file_id')
    file_path, file_arch = AngrProj.id_to_file(file_id)

    _test_zip_file(file_path)

    _test_squash_fs_file(file_path)

    return sys_app_ok_p({'file_path': file_path, 'file_arch': file_arch})
