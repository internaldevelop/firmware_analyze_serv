from fw_analyze.service.pack_info_service import PackInfoService
from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_err_p
from utils.sys.error_code import Error

"""
固件包信息查询
"""


def all_packs_info(request):
    # 所有包的基本信息
    packs_list = PackFileDO.all_packs()
    info_list = []
    for pack in packs_list:
        # 各个包的所含文件信息
        # 各个包的提取任务和分析任务状态
        pack_id = pack['pack_id']
        pack_service = PackInfoService(pack_id, pack)
        pack = pack_service.pack_summary()

        info_list.append(pack)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='查询所有包信息',
                    desc='查询所有固件包的信息，统计其文件数量，查询任务信息')

    return sys_app_ok_p(info_list)


def pack_info(request):
    pack_id = ReqParams.one(request, 'pack_id')

    # 读取指定固件包的信息
    pack_service = PackInfoService(pack_id, None)
    info = pack_service.pack_summary()

    # 保存操作日志
    LogRecords.save('', category='statistics', action='查询包信息',
                    desc='查询指定固件包的信息，统计其文件数量，查询任务信息')

    return sys_app_ok_p(info)


def _file_path_insert_into_tree(tree_obj, file_path, file_id):
    # 判断文件路径的分隔符
    delimiter = '\\' if file_path.find('\\') >= 0 else '/'

    # 分隔字符串成字符串列表
    nodes_list = file_path.split(delimiter)
    node_obj = tree_obj

    for index, node in enumerate(nodes_list):
        # 形如 /bbb/clib，第一个元素是''，空字符串，从第二个元素开始枚举
        if len(node) == 0:
            continue

        if index < len(nodes_list) - 1:
            # 当节点为目录时，添加目录节点
            if node_obj.get(node) is None:
                # 只有目录节点为空时，才添加目录节点
                node_obj[node] = {}
                # 准备下一级节点设置
                node_obj = node_obj[node]
            else:
                # 准备下一级节点设置
                node_obj = node_obj[node]
        else:
            # 当节点为文件时，添加叶子节点（含文件ID和文件路径信息）
            node_obj[node] = {'file_path': file_path, 'file_id': file_id}


def pack_exec_files_tree(request):
    pack_id = ReqParams.one(request, 'pack_id')

    # 读取所有可执行文件
    exec_list = FwFileDO.search_files_of_pack(pack_id, FileType.EXEC_FILE)

    exec_tree = {}
    for exec_file in exec_list:
        # 获取文件路径
        file_path = exec_file['file_path']
        file_id = exec_file['file_id']
        if file_path is None or len(file_path) == 0:
            continue
        _file_path_insert_into_tree(exec_tree, file_path, file_id)

    return sys_app_ok_p(exec_tree)
