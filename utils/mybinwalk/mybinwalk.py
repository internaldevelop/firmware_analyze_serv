import binwalk

class MyBinwalk:

    # 固件文件头自动解码或解析
    def binwalk_scan_signature(filename):
        result_list = list()
        try:
            for module in binwalk.scan(filename, signature=True, quiet=True):
                print("%s Results:" % module.name)
                for result in module.results:
                    result_list.append("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
                    print("\t%s    0x%.8X    %s" % (result.file.path, result.offset, result.description))
        except binwalk.ModuleException as e:
            print("Critical failure:", e)

        return result_list

    # 架构识别
    def binwalk_scan_opcodes(filename):
        # print(filename)
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
            return 'ERROR_INTERNAL_ERROR', e
        return structure

    # 抽取文件
    def binwalk_file_extract(filename):
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

                                list_temp.append(
                                    module.extractor.output[result.file.path].extracted[result.offset].files)

        except binwalk.ModuleException as e:
            print("Critical failure:", e)
            return 'ERROR_INTERNAL_ERROR', e
        return list_temp

    # 抽取文件
    def _binwalk_file_extract(filename, extract_path):
        try:
            list_temp = []
            for module in binwalk.scan(filename, signature=True, quiet=True, extract=True):
                for result in module.results:
                    if result.file.path in module.extractor.output:
                        # These are files that binwalk carved out of the original firmware image, a la dd
                        if result.offset in module.extractor.output[result.file.path].carved:
                            list_temp.append(module.extractor.output[result.file.path].carved[result.offset])

                        # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                        if result.offset in module.extractor.output[result.file.path].extracted:
                            if len(module.extractor.output[result.file.path].extracted[result.offset].files):
                                list_temp.append(module.extractor.output[result.file.path].extracted[result.offset].files)

        except binwalk.ModuleException as e:
            print("Critical failure:", e)
            return 'ERROR_INTERNAL_ERROR', e
        return list_temp