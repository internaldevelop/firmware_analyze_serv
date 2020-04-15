from fw_analyze.service.load_default_pack import LoadDefaultPack
from fw_analyze.service.pack_process_service import PackProcessService
from utils.const.pack_type import PackType
from utils.db.mongodb.logs import LogRecords
from utils.http.response import sys_app_ok_p
from utils.http.request import ReqParams


def _req_pack_types_list(pack_type):
    pack_types_list = []
    if pack_type == PackType.REAL or pack_type == PackType.VIRTUAL:
        pack_types_list.append(pack_type)
    elif pack_type == PackType.ALL:
        pack_types_list.extend([PackType.VIRTUAL, PackType.REAL])
    return pack_types_list


def system_clear_packs(request):
    pack_type = ReqParams.one(request, 'pack_type.int')
    pack_types_list = _req_pack_types_list(pack_type)
    task_list = []
    for pack_type in pack_types_list:
        tasks = PackProcessService.remove_all_packs_by_type(pack_type)
        task_list.extend(tasks)

    # 保存操作日志
    LogRecords.save(task_list, category='sys_admin', action='清除系统固件包',
                    desc='按照系统管理接口的请求参数，清除指定类型的固件包（类型：%d）' % pack_type)

    return sys_app_ok_p({'tasks': task_list})


def system_load_default_packs(request):
    pack_type = ReqParams.one(request, 'pack_type.int')
    pack_types_list = _req_pack_types_list(pack_type)

    pack_list = []
    for pack_type in pack_types_list:
        if pack_type == PackType.VIRTUAL:
            # 装载系统默认虚拟包
            id_list = LoadDefaultPack.load_default_virtual_packs()
        elif pack_type == PackType.REAL:
            # 装载系统默认实体包
            id_list = LoadDefaultPack.load_default_real_packs(range(1, 3))
        pack_list.extend(id_list)

    # 保存操作日志
    LogRecords.save(pack_list, category='sys_admin', action='加载系统默认固件包',
                    desc='按照系统管理接口的请求参数，加载不同类型的系统默认固件包（类型：%d）' % pack_type)

    return sys_app_ok_p({'pack_id_list': pack_list})
