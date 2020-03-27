import urllib.request
from common.response import app_ok_p, app_err_p, app_ok, app_err, sys_app_ok_p, sys_app_err_p, sys_app_ok, sys_app_err
import os
from urllib.request import urlretrieve
from common.utils.general import SysUtils
from common.utils.strutil import StrUtils
from django.conf import settings
import time
from common.error_code import Error

from common.utils.http_request import req_get_param_int, req_get_param, req_post_param, req_post_param_int, req_post_param_dict

from fw_fetch.firmware_db import FirmwareDB

from django.http import HttpResponse, FileResponse
from django.utils.http import urlquote
from urllib.request import urlretrieve

from fw_fetch.firmware_pocs import FirmwarePocs
import re
import urllib.request
from django.conf import settings


class Mydownload:

    @staticmethod
    def fwdownload(downloadurl, savepath, task_id):
        try:
            """
            download file from internet
            :param url: path to download from
            :param savepath: path to save files
            :return: None
            """

            def reporthook(a, b, c):
                """
                显示下载进度
                :param a: 已经下载的数据块
                :param b: 数据块的大小
                :param c: 远程文件大小
                :return: None
                """
                percentage = round(a * b * 100.0 / c, 1)
                # print("\rdownloading: %5.1f%%" % (a * b * 100.0 / c), end="")
                print("\rdownloading: %5.1f%%" % percentage, end="")
                #过程数据写入REDIS


            filename = os.path.basename(downloadurl)
            # 判断是否为合法下载文件名 .zip .bin .img .rar .exe ...
            filetype = 'zip,bin,img,rar,exe'
            file_list = filename.split('.')
            result = file_list[file_list.__len__() - 1] in filetype
            print(result)
            if not result:
                return 'ERROR_FETCH_FILE_TYPE', {'filetype': file_list[file_list.__len__() - 1]}

            # 判断文件是否存在，如果不存在则下载
            if not os.path.isfile(os.path.join(savepath, filename)):
                print('Downloading data from %s' % downloadurl)
                # homepage = 'http://www.comfast.cn/uploadfile/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/OrangeOS-X86-V2.1.0_20170114.zip'
                # 'http://comfast.com.cn/upload/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/CF-AC101-V2.4.0.zip'
                'http://comfast.com.cn/upload/软件驱动/固件/CF-AC101-V2.4.0.zip'
                'http://www.comfast.cn/uploadfile/firmware/CF-AC101-V2.6.1.zip'
                # homepage = homepage.encode()
                print(downloadurl)

                result = urlretrieve(downloadurl, os.path.join(savepath, filename), reporthook=reporthook)

                print('\nDownload finished!', result)
            else:
                print('File already exsits!')

            return 'ERROR_OK', filename, file_list

        except Exception as e:
            print(e)
            return 'ERROR_EXCEPTION', e


