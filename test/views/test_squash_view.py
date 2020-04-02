from utils.db.mongodb.fw_file import FwFile
from utils.fs.fs_image import FsImage
from utils.fs.squashfs import SquashFS
from utils.http.request import ReqParams
from utils.http.response import sys_app_ok_p, sys_app_err


def _test_jffs2_fs_file(file_path):
    # https://gist.github.com/geekman/a0692e912a6e76a777bc
    # https://github.com/sviehb/jefferson
    return


def test_extract_squash_fs(request):
    pack_id = ReqParams.one(request, 'pack_id')

    fs_image = FsImage(pack_id)
    fs_image.extract()

    return sys_app_ok_p({})


def test_squash_fs(request):
    file_id = ReqParams.one(request, 'file_id')
    file_path, file_arch = FwFile.id_to_file(file_id)

    squash = SquashFS(file_path)

    if squash.check_format():
        for i in squash.image.root.findAll():
            print(i.getName())

        for i in squash.image.root.findAllPaths():
            print(i)

    items = []
    nodes = squash.list_all()
    for inode in nodes:
        name, path, folder = squash.node_props(inode)
        items.append(path)
        # content = squash.node_content(inode)
        print(path)

    squash.close()

    return sys_app_ok_p(items)
