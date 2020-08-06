import utils.sys.config
from utils.http.response import sys_app_ok_p, sys_app_ok, sys_app_err
from utils.db.mongodb.fw_file import FwFileDO

# firmware 集合
file_inverted_col = utils.sys.config.g_firmware_db_full["file_inverted_index"]
fw_files_col = utils.sys.config.g_firmware_db_full["fw_files"]
pack_files_col = utils.sys.config.g_firmware_db_full["pack_files"]


class InvertedIndex:

    def read_file(self, file_path):
        result = []
        count = 0
        with open(file_path, 'rb') as file_to_read:
            while True:
                lines = file_to_read.readline()  # read the line
                lines = lines.decode('utf-8', 'ignore')
                if len(lines) == 0:
                    break
                lsplit = lines.split("\t")
                count = count + 1
                if count % 2 == 0:
                    for word in lsplit[0].split(" "):
                        tmp.append(word)
                    result.append(tmp)
                else:
                    tmp = []
                    for word in lsplit[0].split(" "):
                        tmp.append(word)
                if not lines:
                    break
                    pass
        file_to_read.close()
        return result

    # 组件倒排索引
    def inverted(self, file_id):

        file_result = fw_files_col.find({'file_id': file_id})
        file_list = list(file_result)

        if file_list is None or len(file_list) == 0:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        filePo = file_list[0]
        file_path = filePo.get('file_path')

        # file_path = 'E:/samples/argv_test'
        # file_path = 'E:/samples/py_code.txt'

        dict1 = {}
        dict2 = {}
        sentences = InvertedIndex.read_file(self, file_path)

        sentencesLen = len(sentences)

        for i in range(sentencesLen):
            sentence = sentences[i]
            for word in sentence:
                if word == '':
                    continue
                if word.lower() not in dict1:
                    dict1[word.lower()] = set()  # new word
                    dict2[word.lower()] = 1
                else:
                    dict2[word.lower()] += 1
                dict1[word.lower()].add(i + 1)  # update for dictionary

        answer_list = sorted(dict2.items(), key=lambda d: d[1], reverse=True)  # Sort by wordcount of dictionary.
        answer_sort_ascll = sorted(answer_list, key=lambda x: x[0])

        for word in answer_sort_ascll:
            word0 = InvertedIndex.str_to_hex(word[0]).replace('/x0', '')
            sort_dotid = sorted(dict1[word[0]])

            position = ''
            for i in range(len(sort_dotid)):
                position += str(sort_dotid[i])
                if i != (len(sort_dotid) - 1):
                    position += ','

            index_con = word0
            index_con_str = InvertedIndex.hex_to_str(word0)
            appear_total = word[1]

            vulner_info = {'file_id': file_id, 'file_path': file_path, 'index_con': index_con, 'appear_total': appear_total, 'position': position}

            result = file_inverted_col.find({'file_id': file_id, 'index_con': index_con, 'appear_total': appear_total})
            item_list = list(result)

            if (item_list is None or len(item_list) == 0) and len(index_con) > 0 and len(index_con_str) > 10:
                file_inverted_col.save(vulner_info)

        # 对组件列表增加建立 inverted 完成标志
        FwFileDO.set_inverted(file_id)

        return sys_app_ok()

    # 根据倒排索引查询数据
    def get_inverted_data(self, index_con, file_id):
        if index_con is not None and len(index_con) > 0:
            index_con = InvertedIndex.str_to_hex(index_con)
            result = file_inverted_col.find({'index_con': {'$regex': index_con}}).limit(100)
            item_list = list(result)
        elif file_id is not None and len(file_id) > 0:
            result = file_inverted_col.find({'file_id': file_id}).limit(100)
            item_list = list(result)
        else:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        if item_list is None or len(item_list) == 0:
            return sys_app_ok()

        for item_info in item_list:
            item_info.pop("_id")
        return sys_app_ok_p({'total': len(item_list), 'items': item_list})

    # 根据倒排索引查询组件文件
    def get_inverted_fw_data(self, index_con):
        index_con = InvertedIndex.str_to_hex(index_con)
        print(index_con)
        result = file_inverted_col.find({'index_con': {'$regex': index_con}})
        item_list = list(result)
        if item_list is None or len(item_list) == 0:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        file_ids_str = ''
        for filePo in item_list:
            file_id = filePo.get('file_id')

            if file_ids_str.find(file_id) > -1:
                continue
            file_ids_str += file_id + ','

        file_ids = file_ids_str.split(',')

        results = []
        if len(file_ids) > 0:
            files_result = fw_files_col.find({'file_id': {'$in': file_ids}})
            file_list = list(files_result)
            if file_list is None or len(file_list) == 0:
                return sys_app_err('ERROR_INVALID_PARAMETER')

            for file_info in file_list:
                file_info.pop('_id')
                pack_info = pack_files_col.find_one({'pack_id': file_info.get('pack_id')})
                if pack_info is not None:
                    pack_info.pop('_id')
                    file_info['pack_info'] = pack_info

            return sys_app_ok_p({'total': len(file_list), 'files': file_list})

        return sys_app_ok()

    # str转16进制
    def str_to_hex(s):
        return r"/x" + r'/x'.join([hex(ord(c)).replace('0x', '') for c in s])

    # 16进制转str
    def hex_to_str(s):
        return ''.join([chr(i) for i in [int(b, 16) for b in s.split(r'/x')[1:]]])
