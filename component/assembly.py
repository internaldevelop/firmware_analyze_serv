import math

import utils.sys.config
from utils.http.response import sys_app_ok_p, sys_app_err
from utils.db.mongodb.fw_file import FwFileDO
from utils.db.mongodb.make_com_file import MakeCOMFileDO
from utils.db.mongodb.fw_files_storage import FwFilesStorage
from utils.db.mongodb.make_com_file_storage import MakeCOMFilesStorage
fw_files_col = utils.sys.config.g_firmware_db_full["fw_files"]



class Assembly:

    def query(self):
        return "返回"

    # 关键词统计和词频统计，以列表形式返回
    def Count(resfile):
        t = {}
        # infile = open(resfile, 'r')
        infile = open(resfile, 'rb')
        # infile = codecs.open(resfile, 'r', 'utf-16-le')

        f = infile.readlines()
        count = len(f)
        # print(count)
        infile.close()

        # s = open(resfile, 'r')
        s = open(resfile, 'rb')
        # s = codecs.open(resfile, 'r', 'utf-16-le')

        i = 0
        while i < count:
            line = s.readline()
            line = line.decode('utf-8', 'ignore')

            # 去换行符
            line = line.rstrip('\n')

            # print(line)
            words = line.split(" ")
            # print(words)

            for word in words:
                if word != "" and t.__contains__(word):
                    num = t[word]
                    t[word] = num + 1
                elif word != "":
                    t[word] = 1
            i = i + 1

        # 字典按键值降序
        dic = sorted(t.items(), key=lambda t: t[1], reverse=True)
        # print(dic)
        # print()
        s.close()
        return (dic)

    def MergeWord(T1, T2):
        MergeWord = []
        duplicateWord = 0
        for ch in range(len(T1)):
            MergeWord.append(T1[ch][0])
        for ch in range(len(T2)):
            if T2[ch][0] in MergeWord:
                duplicateWord = duplicateWord + 1
            else:
                MergeWord.append(T2[ch][0])

        # print('重复次数 = ' + str(duplicateWord))
        # 打印合并关键词
        # print(MergeWord)
        return MergeWord

    # 得出文档向量
    def CalVector(T1, MergeWord):
        TF1 = [0] * len(MergeWord)

        for ch in range(len(T1)):
            TermFrequence = T1[ch][1]
            word = T1[ch][0]
            i = 0
            while i < len(MergeWord):
                if word == MergeWord[i]:
                    TF1[i] = TermFrequence
                    break
                else:
                    i = i + 1
            # print(TF1)
        return TF1

    def CalConDis(v1, v2, lengthVector):
        # 计算出两个向量的乘积
        B = 0
        i = 0
        while i < lengthVector:
            B = v1[i] * v2[i] + B
            i = i + 1
        # print('乘积 = ' + str(B))

        # 计算两个向量的模的乘积
        A = 0
        A1 = 0
        A2 = 0
        i = 0
        while i < lengthVector:
            A1 = A1 + v1[i] * v1[i]
            i = i + 1
        # print('A1 = ' + str(A1))

        i = 0
        while i < lengthVector:
            A2 = A2 + v2[i] * v2[i]
            i = i + 1
        # print('A2 = ' + str(A2))

        A = math.sqrt(A1) * math.sqrt(A2)

        similarPercent = format(float(B) * 100 / A, ".2f")
        print('两个文件的相似度 = ' + similarPercent)

        return similarPercent

    # fw_file_id 固件文件ID,
    # component_file_id 组件生成文件ID
    # 计算相似度
    def cosine_algorithm(self, fw_file_id, component_file_id):

        # 1 从存储桶导出相关文件
        fw_file_path = FwFilesStorage.export(fw_file_id)
        if fw_file_path is None:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        component_file_path = MakeCOMFilesStorage.export(component_file_id)
        if component_file_path is None:
            return sys_app_err('ERROR_INVALID_PARAMETER')

        # 两篇待比较的文档的路径
        # sourcefile = 'E:/samples/11.txt'
        # s2 = 'E:/samples/22.txt'
        # sourcefile = 'E:/samples/argv_test'
        # s2 = 'E:/samples/argv_test1'

        T1 = Assembly.Count(fw_file_path)
        # print("文档1的词频统计如下：")
        # print(T1)
        T2 = Assembly.Count(component_file_path)
        # print("文档2的词频统计如下：")
        # print(T2)
        # 合并两篇文档的关键词
        mergeword = Assembly.MergeWord(T1, T2)
        # print(mergeword)
        # print(len(mergeword))
        # 得出文档向量
        v1 = Assembly.CalVector(T1, mergeword)
        # print("文档1向量化得到的向量如下：")
        # print(v1)
        v2 = Assembly.CalVector(T2, mergeword)
        # print("文档2向量化得到的向量如下：")
        # print(v2)
        # 计算余弦距离
        cosine_percent = Assembly.CalConDis(v1, v2, len(v1)) + '%'

        return sys_app_ok_p({'cosine_percent': cosine_percent})
