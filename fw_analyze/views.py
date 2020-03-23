from django.shortcuts import render

# Create your my_views here.
from django.http import HttpResponse
from common.utils.http_request import req_get_param
from common.response import app_ok_p, app_err, sys_app_ok_p, sys_app_err
from common.error_code import Error
import binwalk
import angr
from angr.block import CapstoneInsn, CapstoneBlock

from fw_fetch.firmware_db import FirmwareDB

firmware_db = FirmwareDB()


def index(request):
    return HttpResponse("Hello firmware analyze.")


# 固件文件头自动解码或解析
def binwalk_scan_signature(request):
    filename = req_get_param(request, 'filename')
    result_list = list()
    try:
        for module in binwalk.scan(filename, signature=True, quiet=True):
            print("%s Results:" % module.name)
            for result in module.results:
                result_list.append("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
                print("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
    except binwalk.ModuleException as e:
        print("Critical failure:", e)

    return sys_app_ok_p({'decode': result_list})


def binwalk_scan_signatureEx(request):
    firmware_id = req_get_param(request, 'firmware_id')
    try:
        # 查询数据库 得到固件名
        fw = firmware_db.fetch(firmware_id)

        # todo check fw is NULL
        if fw['fw_info']['filepath'] is not None:
            filename = fw['fw_info']['filepath'] + fw['fw_info']['filename'][0]
        else:
            return sys_app_ok_p({'decode': 'Null','description': "解析文件名出错"})

        result_list = list()
        offset_list = list()
        description_list = list()
        index = 0
        # try:
        for module in binwalk.scan(filename, signature=True, quiet=True):
            print("%s Results:" % module.name)
            for result in module.results:
                result_list.append("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
                print("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))

                offset_list.append(result.offset)
                description_list.append(result.description)

        # 将解压缩后的固件文件信息存入mongodb firmware_info
        dic = {}
        item = {}
        for off_set in offset_list:
            index += 1
            offset = 'offset' + str(index)
            description = 'description' + str(index)
            dic[offset] = off_set
            dic[description] = description_list[index-1]

        item['decode_info'] = dic
        firmware_db.update(firmware_id, item)

    except binwalk.ModuleException as e:
        print("Critical failure:", e)

    return sys_app_ok_p({'decode': result_list})

# 架构识别
def binwalk_scan_opcodes(request):
    filename = req_get_param(request, 'filename')
    #print(filename)
    # filename = "D:/code/work/firmwareanalyze/HC5611.bin"
    structure = ''
    try:
        for module in binwalk.scan(filename, opcodes=True, quiet=True):
            print("%s Results:" % module.name)
            for result in module.results:
                print("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
                if ("X86" in result.description.upper()):
                    structure = 'X86'
                    break
                elif ("ARM" in result.description.upper()):
                    structure = "ARM"
                    break
                elif ("MIPS" in result.description.upper()):
                    structure = "MIPS"
                    break
                else:
                    structure = "PowerPC"
                    break
    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'structure': structure,})


# 抽取文件
def binwalk_file_extract(request):
    filename = req_get_param(request, 'filename')
    try:
        list_temp = []
        # filename=US_W331AV1.0BR_V1.0.0.12_cn&en_TD.bin 文件名带特殊符号无法进行抽取文件
        for module in binwalk.scan(filename, signature=True, quiet=True, extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:
                        print
                        "Carved data from offset 0x%X to %s" % (
                        result.offset, module.extractor.output[result.file.path].carved[result.offset])

                        list_temp.append(module.extractor.output[result.file.path].carved[result.offset])
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        if len(module.extractor.output[result.file.path].extracted[result.offset].files):
                            print
                            "Extracted %d files from offset 0x%X to '%s' using '%s'" % (
                            len(module.extractor.output[result.file.path].extracted[result.offset].files),
                            result.offset,
                            module.extractor.output[result.file.path].extracted[result.offset].files[0],
                            module.extractor.output[result.file.path].extracted[result.offset].command)

                            list_temp.append(module.extractor.output[result.file.path].extracted[result.offset].files)

    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'extract': 'ok','filelist':list_temp})


def binwalk_file_extractEx(request):
    # filename = req_get_param(request, 'filename')
    firmware_id = req_get_param(request, 'firmware_id')
    try:
        # 查询数据库 得到固件名
        fw = firmware_db.fetch(firmware_id)

        # todo check fw is NULL
        if fw['fw_info']['filepath'] is not None:
            filename = fw['fw_info']['filepath'] + fw['fw_info']['filename'][0]
        else:
            return sys_app_ok_p({'decode': 'Null','description': "解析文件名出错"})

        list_temp = []

        # filename=US_W331AV1.0BR_V1.0.0.12_cn&en_TD.bin 文件名带特殊符号无法进行抽取文件
        for module in binwalk.scan(filename, signature=True, quiet=True, extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:
                        print
                        "Carved data from offset 0x%X to %s" % (
                        result.offset, module.extractor.output[result.file.path].carved[result.offset])

                        list_temp.append(module.extractor.output[result.file.path].carved[result.offset])
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        if len(module.extractor.output[result.file.path].extracted[result.offset].files):
                            print
                            "Extracted %d files from offset 0x%X to '%s' using '%s'" % (
                            len(module.extractor.output[result.file.path].extracted[result.offset].files),
                            result.offset,
                            module.extractor.output[result.file.path].extracted[result.offset].files[0],
                            module.extractor.output[result.file.path].extracted[result.offset].command)

                            list_temp.append(module.extractor.output[result.file.path].extracted[result.offset].files)

        # 将抽取的文件信息存入mongodb firmware_info
        dic = {}
        item = {}
        index = 0
        for off_set in list_temp:
            index += 1
            filex = 'file' + str(index)
            dic[filex] = list_temp[index-1]

        item['extract_info'] = dic
        firmware_db.update(firmware_id, item)

    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'extract': 'ok','filelist':list_temp})


def binwalk_file_test(request):
    filename = req_get_param(request, 'filename')
    try:

        for module in binwalk.scan(filename, filesystem=True, quiet=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:
                        print
                        "Carved data from offset 0x%X to %s" % (
                        result.offset, module.extractor.output[result.file.path].carved[result.offset])
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        print
                        "Extracted %d files from offset 0x%X to '%s' using '%s'" % (
                        len(module.extractor.output[result.file.path].extracted[result.offset].files),
                        result.offset,
                        module.extractor.output[result.file.path].extracted[result.offset].files[0],
                        module.extractor.output[result.file.path].extracted[result.offset].command)


    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'extract': 'ok',})


# binwalk 识别架构
def getarch(filename):
    structure = ''
    try:
        for module in binwalk.scan(filename, opcodes=True, quiet=True):
            print("%s Results:" % module.name)
            for result in module.results:
                print("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
                if ("X86" in result.description.upper()):
                    structure = 'x86'
                    break
                elif ("ARM" in result.description.upper()):
                    structure = "arm"
                    break
                elif ("MIPS" in result.description.upper()):
                    structure = "mips"
                    break
                else:
                    structure = "powerpc"
                    break

    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return structure
    return structure


# 转换成中间代码
def angr_convert2asm(request):
    insns = []
    asms = []
    try:
        filename = req_get_param(request, 'filename')
        arch = getarch(filename)
        p = angr.Project(filename, load_options={
            'auto_load_libs': False,
            'main_opts': {
                'backend': 'blob',
                'base_addr': 0,
                'arch': arch,
            },
        })
        maxadd = p.loader.max_addr
        minadd = p.loader.min_addr
        print(minadd, maxadd)

        # let's disasm with capstone to search targets
        insn_bytes = p.loader.memory.load(0, maxadd)

        for cs_insn in p.arch.capstone.disasm(insn_bytes, 0):
            insns.append(CapstoneInsn(cs_insn))
            print("0x%x:\t%s\t\t%s" % (cs_insn.address, cs_insn.mnemonic, cs_insn.op_str))
            # print(str(CapstoneInsn(cs_insn)))
        block = CapstoneBlock(0, insns, 0, p.arch)

        for ins in block.insns:
            asms.append(str(ins))
            # print(ins)

    except Exception as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'ASM': asms, })


# 转换成中间代码
def angr_convert_code(request):
    try:
        filename = req_get_param(request, 'filename')
        arch = getarch(filename)
                                      # load_options = {'auto_load_libs': False, 'main_opts': {'base_addr': 0}})
        # proj = angr.Project(filename, load_options={
        #     'main_opts': {
        #         'backend': 'blob',
        #         'base_addr': 0,
        #         'arch': arch,
        #     },
        # })

        # 装载二进制程序
        proj = angr.Project(filename, load_options={
            'auto_load_libs': False,
            'main_opts': {
                'backend': 'blob',
                'base_addr': 0,
                'arch': arch,
            },
        })


        print(proj.arch)
        state = proj.factory.entry_state()

        print(proj.entry)
        #### Blocks # 转换入口点为基本块
        block = proj.factory.block(proj.entry)       # lift a block of code from the program's entry point
        pp = block.pp()                        # pretty-print a disassembly to stdout
        print(block.instructions)              # how many instructions are there?
        print(block.instruction_addrs)         # what are the addresses of the instructions?
        print(block.capstone)                  # capstone disassembly
        print(block.vex)                       # VEX IRSB (that's a python internal address, not a program address)

        irsb = proj.factory.block(proj.entry).vex
        irsb.pp()
        irsb.next.pp()


    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'code': str(block.vex),})


# 函数识别
def angr_recognize_func(request):
    functions = []
    try:
        filename = req_get_param(request, 'filename')
        arch = getarch(filename)
        proj = angr.Project(filename, load_options={
            'auto_load_libs': False,
            'main_opts': {
                'backend': 'blob',
                'base_addr': 0,
                'arch': arch,
            },
        })
        cfg = proj.analyses.CFGFast()
        for address, func in cfg.functions.items():
            print(hex(address), func.name)
            functions.append(func.name)

    except binwalk.ModuleException as e:
        print("Critical failure:", e)
        return sys_app_err('ERROR_INTERNAL_ERROR')
    return sys_app_ok_p({'functions': functions,})