from dateutil.relativedelta import relativedelta
import json
from datetime import date, datetime, timedelta

import os
import tarfile
import os.path
import zipfile
import rarfile
import patoolib
import py7zr
# from easy7zip import easy7zip
# from py7zr import pack_7zarchvie, unpack_7zarchive
from py7zr import unpack_7zarchive
import shutil
from django.conf import settings


def enum(*args):
    enums = dict(zip(args, range(len(args))))
    return type('Enum', (), enums)


class SysUtils:

    # @staticmethod
    # def makedir(self, name):
    #     path = os.path.join(self.base_path, name)
    #     isExist = os.path.exists(path)
    #     if not isExist:
    #         os.makedirs(path)
    #         print("File has been created.")
    #     else:
    #         print('OK!The file is existed. You do not need create a new one.')
    #     os.chdir(path)

    @staticmethod
    def get_now_time():
        return datetime.now()

    @staticmethod
    def get_now_time_str():
        return SysUtils.get_now_time().strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def parse_time_str(time_str):
        return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')

    @staticmethod
    def elapsed_time_ms(start_time):
        now_time = SysUtils.get_now_time()
        delta_time = now_time - start_time
        return delta_time.seconds * 1000.0 + delta_time.microseconds / 1000.0

    @staticmethod
    def get_time_delta_days(delta_days):
        now = datetime.now()
        new_time = now + timedelta(days=delta_days)
        return new_time

    @staticmethod
    def get_time_delta_years(delta_years):
        now = datetime.now()
        new_time = now + relativedelta(years=delta_years)
        return new_time

    @staticmethod
    def print_time(time):
        print(time)

    @staticmethod
    def copy_dict(src_dict, key_list):
        dest_dict = {}
        for key in key_list:
            if key in src_dict.keys():
                dest_dict[key] = src_dict[key]
            else:
                dest_dict[key] = ''
        return dest_dict

    @staticmethod
    def grid_out_to_dict(grid_out):
        if grid_out is None:
            return None
        dest_dict = {'filename': grid_out.filename, 'aliases': grid_out.aliases[0],
                     'content_type': grid_out.content_type, 'length': grid_out.length, 'name': grid_out.name}
        # dest_dict['content'] = grid_out.read()
        return dest_dict

    @staticmethod
    def match_convert(template, input):
        temp_src = []
        temp_dest = []
        for item in template:
            temp_src.append(item[0])
            temp_dest.append(item[1])
        try:
            index = temp_src.index(input)
        except ValueError:
            return None
        else:
            return temp_dest[index]

    @staticmethod
    def parse_file_suffix(file_path):
        parsed = os.path.splitext(file_path)
        name = parsed[0]
        suffix = parsed[1].lstrip('.').lower()
        return suffix

    @staticmethod
    def add_plain_text_file_suffix(file_path):
        not_plain_text_suffixs = ['docx', 'eml', 'exe', 'gz', 'ics', 'mid', 'pdf', 'pm', 'rar', 'sys', 'xsl', 'zip', ]
        suffix = SysUtils.parse_file_suffix(file_path)
        if suffix in not_plain_text_suffixs:
            return file_path + '.bin'
        return file_path + '.txt'

    @staticmethod
    def parse_file_type(file_path):
        suffix = SysUtils.parse_file_suffix(file_path)
        template = [['as', 'Action Script'], ['asc', 'Active Server Pages'], ['asm', 'ASM'],
                    ['asp', 'Active Server Pages'], ['bat', 'Batch'], ['c', 'C'], ['cfm', 'ColdFusion Markup'],
                    ['cpp', 'C++'], ['cob', 'COBOL'], ['cs', 'C#'], ['delphi', 'delphi'], ['docx', 'Word'],
                    ['eml', 'Email'], ['exe', 'Execute'], ['go', 'Golang'], ['gz', 'gzip'], ['htm', 'html'],
                    ['html', 'html'], ['ics', 'Calendar'], ['java', 'java'], ['js', 'Java Script'],
                    ['jsp', 'Java Server Page'], ['mid', 'MIDI'], ['md', 'Mark Down'], ['nasl', 'Nessus Script'],
                    ['nasm', 'ASM'], ['nse', 'Nmap Script'], ['pas', 'Pascal'], ['pdf', 'PDF'], ['php', 'PHP'],
                    ['pl', 'Perl'], ['pm', 'Perl Module'], ['py', 'python'], ['rar', 'rar'], ['rb', 'ruby'],
                    ['s', 'ASM'], ['sh', 'Shell Script'], ['sql', 'SQL'], ['sys', 'system'], ['tcsh', 'TCSH Script'],
                    ['txt', 'Text'], ['vb', 'Visual Basic'], ['vbs', 'VB Script'], ['wsf', 'Windows Script'],
                    ['xml', 'XML'], ['xhtml', 'XML html'], ['xsl', 'Excel'], ['zip', 'zip'], ]
        # template = [['pdf', 'PDF'], ]
        type = SysUtils.match_convert(template, suffix)
        if type is None:
            type = 'unknown'
        return type

    # 解压tgz压缩文件
    @staticmethod
    def un_tgz(filename):
        tar = tarfile.open(filename)
        # 判断同名文件夹是否存在，若不存在则创建同名文件夹
        SysUtils.check_filepath(os.path.splitext(filename)[0])

        tar.extractall(os.path.splitext(filename)[0])
        tar.close()

    @staticmethod
    def un_tar(file_name):
        # untar zip file"""
        tar = tarfile.open(file_name)
        names = tar.getnames()
        SysUtils.check_filepath(file_name + "_files")

        # 由于解压后是许多文件，预先建立同名文件夹
        for name in names:
            tar.extract(name, file_name + "_files/")
        tar.close()

    # 解压rar压缩包
    @staticmethod
    def un_rar(filename, extract_dir):
        try:
            rar = rarfile.RarFile(filename)
            # 判断同名文件夹是否存在，若不存在则创建同名文件夹
            SysUtils.check_filepath(os.path.splitext(filename)[0])

            rar.extractall(path=extract_dir)
            return rar.namelist()

        except Exception as e:
            print(e)
            return ""

    @staticmethod
    def un_zip(filename, extract_dir):
        # zip_file2_path = r'F:\tk_demo.zip'
        # zipfile提供的压缩方法有：
        # ZIP_STORED，ZIP_DEFLATED， ZIP_BZIP2和ZIP_LZMA
        # ZIP_STOREED：只是作为一种存储，实际上并未压缩
        # ZIP_DEFLATED：用的是gzip压缩算法
        # ZIP_BZIP2：用的是bzip2压缩算法
        # ZIP_LZMA：用的是lzma压缩算法
        # unzip_files = zipfile.ZipFile(filename, mode='r', compression=zipfile.ZIP_STORED)
        try:
            unzip_files = zipfile.ZipFile(filename, mode='r')
            unzip_files.extractall(extract_dir)
            unzip_files.close()
            return unzip_files.namelist()
        except Exception as e:
            print(e)
            return ""

    @staticmethod
    def un_patool(filename):
        # patoolib.extract_archive(filename, outdir="/tmp")
        patoolib.extract_archive(filename)

    @staticmethod
    def uncompress(filename, extract_dir):
        try:
            # 判断文件类型 进一步处理 zip , trx ,rar
            list = SysUtils.un_py7zr(filename, extract_dir)  #for http://www.luyoudashi.com/roms/
            if len(list) == 0:
                list = SysUtils.un_zip(filename, extract_dir)  #for http://www.comfast.cn
            if len(list) == 0:
                list = SysUtils.un_rar(filename, extract_dir)

        except Exception as e:
            print(e)
            return ""

        return list

    @staticmethod
    def un_py7zr(filename, extract_dir):
        list = []
        try:
            is7z = py7zr.is_7zfile(filename)
            if is7z:
                ret = py7zr.unpack_7zarchive(filename, extract_dir)
                arc = py7zr.SevenZipFile(filename)
                list = arc.getnames()
                # print(list)
            else:
                print('unknow file type')
        except Exception as e:
            print(e)
        return list

    @staticmethod
    def un_7z(filename):
        # register file format at first.
        # shutil.register_archive_format('7zip', pack_7zarchive, description='7zip archive')
        shutil.register_unpack_format('7zip', ['.7z'], unpack_7zarchive)
        # extraction
        shutil.unpack_archive(filename)

    # 检查本地保存路径 没有则创建
    @staticmethod
    def check_filepath(path):
        # 去除首位空格
        path = path.strip()
        # 去除尾部 \ 符号
        path = path.rstrip("\\")

        # 判断路径是否存在 # 存在     True        # 不存在   False
        isExists = os.path.exists(path)

        # 判断结果
        if not isExists:
            # 如果不存在则创建目录
            os.makedirs(path)
            print(path + ' 创建成功')
            return True
        else:
            # 如果目录存在则不创建，并提示目录已存在
            print(path + ' 目录已存在')
            return False


class TimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)
