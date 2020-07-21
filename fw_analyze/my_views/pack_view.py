from fw_analyze.service.pack_info_service import PackInfoService
from utils.const.file_type import FileType
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.logs import LogRecords
from utils.db.mongodb.pack_file import PackFileDO
from utils.gadget.my_tree import MyTree
from utils.http.request import ReqParams
from utils.http.response import app_err, sys_app_ok_p, sys_app_err_p
from utils.sys.error_code import Error
from utils.db.mongodb.make_com_file import MakeCOMFileDO
from utils.db.mongodb.pack_com_file import PackCOMFileDO
from utils.task.my_task import MyTask
from utils.task.task_type import TaskType
from component.assembly import Assembly
from component.inverted_index import InvertedIndex
from utils.gadget.general import SysUtils
import utils.sys.config
import multiprocessing
import os
from utils.cache.redis import MyRedis

assembly = Assembly()
invertedIndex = InvertedIndex()

g_runing_flag = False

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
                    desc='查询指定固件包（ID=%s）的信息，统计其文件数量，查询任务信息' % pack_id)

    return sys_app_ok_p(info)


# 检查组件关联
# 固件里文件名与组件名匹配，相同则认为是组件
def check_component(pack_id, task_id):

    MyRedis.set('running_check_com_flag', True)

    # 获取本固件包所有的二进制可执行文件记录
    fw_files_list = FwFileDO.search_files_of_pack(pack_id, FileType.EXEC_FILE)

    # 枚举每个文件，根据文件名检索组件库（make），校验
    total_count = len(fw_files_list)
    for index, file_item in enumerate(fw_files_list):
        percentage = round(index * 100 / total_count, 1)
        MyTask.save_exec_info(task_id, percentage)

        componentinfo = MakeCOMFileDO.search_component_name(file_item['file_name'])
        if componentinfo is None:
            continue
        FwFileDO.set_component(file_item['file_id'], 1)
        # 相似度匹配计算，标记漏洞(version / edbid)
        fw_file_id = file_item['file_id']
        component_file_id = componentinfo['file_id']

        print(SysUtils.get_now_time())
        # 计算相似度 比较耗时 openssl计算大约两分钟
        similarity = assembly.calc_cosine_algorithm(fw_file_id, component_file_id)
        print(SysUtils.get_now_time())

        # todo 相似度阈值设定： 0－100
        if similarity < 50:
            print(similarity)
            continue
        # 相似度大于阈值 标记漏洞(version / edbid)
        com_file_info = PackCOMFileDO.fetch_pack(componentinfo['pack_id'])
        version = com_file_info['version']
        name = com_file_info['name']
        edb_id = com_file_info['edb_id']
        FwFileDO.set_component_extra_props(fw_file_id, {'version': version, 'name': name, 'edb_id': edb_id})

    MyRedis.set('running_check_com_flag', False)

    # 保存任务完成状态
    MyTask.save_exec_info(task_id, 100.0)

    return


def start_check_component_task(pack_id):

    # 检查组件关联是否运行，运行中则跳过
    isrun = MyRedis.get('running_check_com_flag')
    if isrun:
        return

    # # 检查组件关联
    # check_component(pack_id, FileType.EXEC_FILE)
    # 修改为任务处理方式进行检查组件关联 关联组件标记，相似度匹配计算，标记漏洞(version/edbid)
    # 启动编译任务
    extra_info = {'task_type': TaskType.COMPONENT_CHECK,
                  'task_name': '检查组件关联',
                  'task_desc': '检查组件关联,相似度匹配计算，标记漏洞(version/edbid)'}
    task = MyTask(check_component, (pack_id,), extra_info=extra_info)
    task_id = task.get_task_id()


# 查询所有组件文件目录树
def com_files_tree(request):
    tree_type = ReqParams.one(request, 'tree_type')
    # 读取所有组件文件
    com_list = FwFileDO.search_all_com_files()

    if tree_type is None or len(tree_type) == 0 or tree_type == 'normal':
        tree_type = 'normal'
        exec_tree = {}
    elif tree_type == 'antd':
        exec_tree = []
    else:
        tree_type = 'normal'
        exec_tree = {}

    # 对每个文件做树的各级节点定位和创建
    for exec_file in com_list:
        # 获取文件路径
        file_path = exec_file['file_path']
        file_id = exec_file['file_id']

        component = exec_file['component']

        if file_path is None or len(file_path) == 0:
            continue

        if tree_type == 'normal':
            MyTree.file_path_insert_into_tree(exec_tree, file_path, file_id)
        elif tree_type == 'antd':
            MyTree.file_path_insert_into_antd_tree(exec_tree, file_path, file_id)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='查询所有组件文件目录树',
                    desc='获取所有组件文件目录树结构（模式为：%s）' % (tree_type))

    return sys_app_ok_p(exec_tree)



def pack_exec_files_tree(request):
    pack_id, tree_type = ReqParams.many(request, ['pack_id', 'tree_type'])

    start_check_component_task(pack_id)
    # # # 检查组件关联
    # # check_component(pack_id, FileType.EXEC_FILE)
    # # 修改为任务处理方式进行检查组件关联 关联组件标记，相似度匹配计算，标记漏洞(version/edbid)
    # # 启动编译任务
    # extra_info = {'task_type': TaskType.COMPONENT_CHECK,
    #               'task_name': '检查组件关联',
    #               'task_desc': '检查组件关联,相似度匹配计算，标记漏洞(version/edbid)'}
    # task = MyTask(check_component, (pack_id,), extra_info=extra_info)
    # task_id = task.get_task_id()

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

    # 对每个文件做树的各级节点定位和创建
    for exec_file in exec_list:
        # 获取文件路径
        file_path = exec_file['file_path']
        file_id = exec_file['file_id']

        component = exec_file['component']
        # if exec_file['component'] is not None:
        #     component = exec_file['component']
        # else:
        #     component = 0

        if file_path is None or len(file_path) == 0:
            continue

        if tree_type == 'normal':
            MyTree.file_path_insert_into_tree(exec_tree, file_path, file_id, component)
        elif tree_type == 'antd':
            MyTree.file_path_insert_into_antd_tree(exec_tree, file_path, file_id, component)

    # 保存操作日志
    LogRecords.save('', category='statistics', action='读取固件包文件结构',
                    desc='获取指定固件包（ID=%s）的文件结构（模式为：%s）' % (pack_id, tree_type))

    return sys_app_ok_p(exec_tree)
