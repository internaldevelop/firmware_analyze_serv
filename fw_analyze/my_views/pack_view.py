from fw_analyze.service.pack_info_service import PackInfoService
from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.gadget.my_tree import MyTree
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


def pack_exec_files_tree(request):
    pack_id, tree_type = ReqParams.many(request, ['pack_id', 'tree_type'])

    # 读取所有可执行文件
    exec_list = FwFileDO.search_files_of_pack(pack_id, FileType.EXEC_FILE)

    if tree_type is None or len(tree_type) == 0 or tree_type == 'normal':
        # file_path_insert_into_tree 树，初始化为字典
        tree_type = 'normal'
        exec_tree = {}
    elif tree_type == 'antd':
        # file_path_insert_into_antd_tree 树，初始化为数组
        exec_tree = []
    else:
        tree_type = 'normal'
        exec_tree = {}

    for exec_file in exec_list:
        # 获取文件路径
        file_path = exec_file['file_path']
        file_id = exec_file['file_id']
        if file_path is None or len(file_path) == 0:
            continue

        if tree_type == 'normal':
            MyTree.file_path_insert_into_tree(exec_tree, file_path, file_id)
        elif tree_type == 'antd':
            MyTree.file_path_insert_into_antd_tree(exec_tree, file_path, file_id)

    return sys_app_ok_p(exec_tree)
