from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.fs.pack_files import PackFiles
from utils.fs.squashfs import SquashFS
from utils.gadget.my_path import MyPath
from utils.gadget.strutil import StrUtils
from utils.const.file_type import FileType
import os

from utils.task.my_task import MyTask
from utils.task.task_type import TaskType


class FsImage:

    def __init__(self, pack_id):
        self.pack_id = pack_id

    def open_image(self):
        # 查找指定包的 FS 镜像文件
        file_docs = FwFileDO.search_files_of_pack(self.pack_id, FileType.FS_IMAGE)
        if len(file_docs) == 0:
            return
        # 只取第一个镜像文件
        image_file = file_docs[0]

        # 导出镜像文件到临时目录
        image_file_path = FwFilesStorage.export(image_file['file_id'])

        # 尝试 SquashFS 解析，并验证
        image = SquashFS(image_file_path)
        # if image.check_format():
        #     pass
        return image

    @staticmethod
    def start_fs_image_extract_task(pack_id):
        fs_image = FsImage(pack_id)
        # if fs_image.image is None:
        #     return

        extra_info = {'pack_id': pack_id, 'task_type': TaskType.FS_EXTRACT,
                      'task_name': '文件系统解析',
                      'task_desc': '从文件系统镜像包中提取文件，判断文件类型，并保存文件内容到数据库中。'}
        task = MyTask(fs_image.fs_image_extract, (pack_id,), extra_info=extra_info)

    def fs_image_extract(self, pack_id, task_id):
        image = self.open_image()

        # 在主进程或任务中，采用预订的文件系统抽取文件
        image.extract_files(extract_func=self.save_proc)

        # 保存任务完成状态
        MyTask.save_exec_info(task_id, 100.0)

        # 完成抽取后，启动任务检验该包中所有可执行二进制文件的验证
        PackFiles.start_exec_bin_verify_task(self.pack_id)

    def save_proc(self, name, path, file_type, content, extra_props=None):
        name = str(name)
        file_id = StrUtils.uuid_str()

        # 保存文件参数
        FwFileDO.save_file_item(self.pack_id, file_id, name, file_type, file_path=path, extra_props=extra_props)
        # 保存文件内容
        FwFilesStorage.save(file_id, name, path, file_type, content)

    def enum_files(self):
        image = self.open_image()
        image.extract_files()

