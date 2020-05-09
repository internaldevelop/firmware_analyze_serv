# Create your my_views here.
import time
import datetime

from utils.http.request import ReqParams
from utils.http.response import app_ok_p, app_err_p, app_ok, app_err, sys_app_ok_p, sys_app_err_p, sys_app_ok, sys_app_err
from utils.sys.error_code import Error

from utils.http.http_request import req_get_param_int, req_get_param, req_post_param, req_post_param_int, req_post_param_dict
from utils.gadget.general import SysUtils
from utils.gadget.strutil import StrUtils

from utils.task.my_task import MyTask
from fw_fetch.firmware_db import FirmwareDB
from utils.gadget.download import Mydownload

from django.http import HttpResponse, FileResponse
from django.utils.http import urlquote
from urllib.request import urlretrieve

from fw_fetch.firmware_pocs import FirmwarePocs
import re
import urllib.request
import os
from urllib.request import urlretrieve
from bs4 import BeautifulSoup
from django.conf import settings

from utils.websocket.websocket import MyWebsocket
from utils.db.mongodb.mongo_db import MongoDB

# firmware 信息集合
import utils.sys.config
import json
# import urllib.parse
# import urllib.request

firmware_info_coll = utils.sys.config.g_firmware_info_col
task_info_coll = utils.sys.config.g_task_info_col

firmware_db = FirmwareDB()
firmware_pocs = FirmwarePocs()
# edb_stat = EdbStat()


def index(request):
    return HttpResponse("Hello firmware fetch.")


def test_http_get():


    url = "http://" + utils.g_java_service_ip + ":10901/firmware/setdata"

    v1= {}
    v1['1'] = "123"
    v1['2'] = "234"
    v1['3'] = "345"
    data = json.dumps(v1)

    # 定义请求数据，并且对数据进行赋值
    values = {}
    values['task_uuid'] = StrUtils.uuid_str()
    values['datas'] = data

    # # 对请求数据进行编码
    # data = urllib.parse.urlencode(values).encode('utf-8')
    # print(type(data))  # 打印<class 'bytes'>
    # print(data)  # 打印b'status=hq&token=C6AD7DAA24BAA29AE14465DDC0E48ED9'

    # 若为post请求以下方式会报错TypeError: POST data should be bytes, an iterable of bytes, or a file object. It cannot be of type str.
    # Post的数据必须是bytes或者iterable of bytes,不能是str,如果是str需要进行encode()编码
    data = urllib.parse.urlencode(values)
    print(type(data))  # 打印<class 'str'>
    print(data)  # 打印status=hq&token=C6AD7DAA24BAA29AE14465DDC0E48ED9

    # 将数据与url进行拼接
    req = url + '?' + data
    # 打开请求，获取对象
    response = urllib.request.urlopen(req)

    print("get complate")
    # print(type(response))  # 打印<class 'http.client.HTTPResponse'>
    # # 打印Http状态码
    # print(response.status)  # 打印200
    # # 读取服务器返回的数据,对HTTPResponse类型数据进行读取操作
    # the_page = response.read()
    # # 中文编码格式打印数据
    # print(the_page.decode("unicode_escape"))

def test1():
    ws = MyWebsocket()
    ws.sendmsg("hello00000000")
    ws.sendmsg("task_uuid:1234321,data:xxxxxx")
    # MyWebsocket.sendmsg("testhello")


def testws(request):
    # test1()

    # http get
    test_http_get()
    return sys_app_ok_p('test ok')


def test(request):
    print("run into test")
    # filename = 'C:\\GIT\\firmware_analyze_serv\\firmware\\_CF-AC101-V2.6.1.bin.extracted\\12F304.squashfs'
    # list = SysUtils.un_py7zr(filename, settings.FW_PATH)
    # list = SysUtils.un_py7zrEx(filename)


    # SysUtils.un_tgz(filename)
    # SysUtils.un_tar(filename)
    # SysUtils.un_rar(filename)
    return sys_app_ok_p('test ok')


# 1.1 指定URL下载固件
def fwdownload(request):
    print("run into fwdownload")
    homepage = req_get_param(request, 'url')
    print(homepage)

    # 爬取下载固件
    # firmware = Firmware()

    # 普联 TP-Link
    savepath = "TP-Link"
    # firmware.makedir(savepath)
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-13350-"
    for i in range(5):  # 控制爬取的页数
        # firmware.get_firmware(url, i+1)
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 水星 Mercury
    savepath = "Mercury"
    firmware_db.makedir(savepath)
    # url = "http://www.luyoudashi.com/roms/vendor-8080-"
    url = homepage + "/roms/vendor-8080-"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 智能固件 OpenWRT
    # 迅捷 Fast
    savepath = "Fast"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-4588.html"
    get_firmware(url, savepath)

    # 斐讯 Phicomm  http://www.luyoudashi.com/roms/vendor-11367.html
    savepath = "Phicomm"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-11367-"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 腾达 Tenda
    savepath = "Tenda"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-12997-"
    for i in range(4):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 磊科 Netcore
    savepath = "Netcore"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-8806-"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 网件 NETGEAR
    savepath = "NETGEAR"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-8819-"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 小米 Xiaomi
    savepath = "Xiaomi"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-14593.html"
    get_firmware(url, savepath)

    # D-Link   固件下载
    savepath = "D-Link"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-3132-"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 极路由 HiWiFi
    savepath = "HiWiFi"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-16501.html"
    for i in range(2):  # 控制爬取的页数
        url = url + str(i+1) + ".html"
        get_firmware(url, savepath)
        break

    # 新路由 Newifi
    savepath = "Newifi"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-16502.html"
    get_firmware(url, savepath)

    # 华硕 ASUS
    savepath = "ASUS"
    firmware_db.makedir(savepath)
    url = homepage + "/roms/vendor-1130.html"
    get_firmware(url, savepath)
    # if fwdownload is None:
    #     return app_err(Error.FAIL_QUERY)
    # else:
    return sys_app_ok_p('ERROR_OK')


# 1.1 指定URL下载固件
def fwdownloadex(request):
    # print(Sys_code_err)
    print("run into fwdownload")

    # 获取下载URL
    downloadurl = req_get_param(request, 'url')
    print(downloadurl)
    savepath = settings.FW_PATH
    if os.path.isdir(savepath):
        pass
    else:
        os.mkdir(savepath)

    # 获取数据库固件ID
    firmware_id = firmware_db.get_suggest_firmware_id(None)
    item = {
        'firmware_id': firmware_id
            }

    # 任务ID 同固件ID
    task_id = firmware_db.get_suggest_task_id(None)
    task_item = {
        'task_id': task_id
            }

    task_item['task_id'] = task_id
    task_item['type'] = 'download'
    task_item['percentage'] = ''
    task_item['status'] = '0'
    firmware_db.task_add(task_item)

    # download_info = Mydownload.fwdownload(downloadurl,savepath)
    # print(download_info)

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

            task_item['percentage'] = percentage
            firmware_db.task_update(task_id, task_item)

        filename = os.path.basename(downloadurl)
        # 判断是否为合法下载文件名 .zip .bin .img .rar .exe ...
        filetype = 'zip,bin,img,rar,exe'
        file_list = filename.split('.')
        result = file_list[file_list.__len__() - 1] in filetype
        print(result)
        if not result:
            #
            return sys_app_err_p('ERROR_FETCH_FILE_TYPE', {'filetype': file_list[file_list.__len__() - 1]})

        # 判断文件是否存在，如果不存在则下载
        if not os.path.isfile(os.path.join(savepath, filename)):
            print('Downloading data from %s' % downloadurl)
            # homepage = 'http://www.comfast.cn/uploadfile/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/OrangeOS-X86-V2.1.0_20170114.zip'
            # 'http://comfast.com.cn/upload/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/CF-AC101-V2.4.0.zip'
            'http://comfast.com.cn/upload/软件驱动/固件/CF-AC101-V2.4.0.zip'
            'http://www.comfast.cn/uploadfile/firmware/CF-AC101-V2.6.1.zip'
            # homepage = homepage.encode()
            print(downloadurl)

            urlretrieve(downloadurl, os.path.join(savepath, filename), reporthook=reporthook)

            item['fw_file_name'] = filename
            item['application_mode'] = file_list[0]
            item['fw_manufacturer'] = ''
            firmware_db.add(item)

            # task_item['type'] = file_list[0]
            # task_item['status'] = ''
            # task_item['remark'] = ''
            # firmware_db.task_add(task_item)

            pathfilename = savepath+"\\"+filename
            with open(pathfilename, 'rb') as myimage:
                data = myimage.read()
                firmware_pocs.add(firmware_id, filename, data)

            print('\nDownload finished!')
        else:
            print('File already exsits!')
        # 获取文件大小
        filesize = os.path.getsize(os.path.join(savepath, filename))
        # 文件大小默认以Bytes计， 转换为Mb
        print('File size = %.2f Mb' % (filesize / 1024 / 1024))
        return sys_app_ok_p('ERROR_OK')
    except Exception as e:
        print(e)
        return sys_app_err(e)


# 1.2 查询固件列表
def list(reuqest):
    # 获取信息总数
    total = firmware_db.info_count()

    # 读取固件信息
    docs = firmware_db.query(0, total)
    #SysLog.success('查询漏洞', '成功查询漏洞信息，查询到漏洞信息总数={}'.format(len(docs)))
    return sys_app_ok_p({'total': total, 'count': len(docs), 'items': docs})


def query(request):
    offset = req_get_param_int(request, 'offset')
    count = req_get_param_int(request, 'count')

    # 获取信息总数
    total = firmware_db.info_count()
    # 指定偏移量越界，则报错
    if offset >= total:
        return app_err_p(Error.NO_MORE_DATA, {'total': total, 'count': 0})

    # 读取利用信息
    docs = firmware_db.query(offset, count)
    #SysLog.success('查询漏洞', '成功查询漏洞信息，查询到漏洞信息总数={}'.format(len(docs)))
    return app_ok_p({'total': total, 'count': len(docs), 'items': docs})


def fetch(request):
    firmware_id = req_get_param(request, 'firmware_id')
    if StrUtils.is_blank(firmware_id):
        return sys_app_err('ERROR_INVALID_PARAMETER')
    doc = firmware_db.fetch(firmware_id)
    if doc is None:
        #SysLog.fail('提取漏洞', '没有提取到漏洞信息（ID={}）'.format(firmware_id))
        return sys_app_err('ERROR_FWID_NOT_FOUND')
    #SysLog.success('提取漏洞', '成功提取漏洞信息（ID={}）'.format(firmware_id))
    return app_ok_p(doc)


def filter(request):
    offset = req_get_param_int(request, 'offset')
    count = req_get_param_int(request, 'count')
    field = req_get_param(request, 'field')
    value = req_get_param(request, 'value')

    # 查找利用信息
    result_cursor = firmware_db.filter(field, value)
    if result_cursor is None:
        return app_err(Error.INVALID_REQ_PARAM)
    item_list = list(result_cursor)

    # 获取信息总数，并判断指定偏移量是否越界
    total = len(item_list)
    if total == 0 or offset >= total:
        return app_err_p(Error.NO_MORE_DATA, {'total': total, 'count': 0})

    # 读取指定位置和数量的利用信息
    if count > total - offset:
        count = total - offset
    item_list = item_list[offset: offset + count]
    #SysLog.success('查询漏洞', '成功查询漏洞信息，查询到漏洞信息总数={}'.format(len(item_list)))
    return app_ok_p({'total': total, 'count': len(item_list), 'items': item_list})


def search(request):
    offset = req_get_param_int(request, 'offset')
    count = req_get_param_int(request, 'count')
    value = req_get_param(request, 'value')

    # 查找利用信息
    result_cursor = firmware_db.search(value)
    item_list = list(result_cursor)

    # 获取信息总数，并判断指定偏移量是否越界
    total = len(item_list)
    if total == 0 or offset >= total:
        return app_err_p(Error.NO_MORE_DATA, {'total': total, 'count': 0})

    # 读取指定位置和数量的利用信息
    if count > total - offset:
        count = total - offset
    item_list = item_list[offset: offset + count]
    # 为性能测试中降低CPU使用率，小段延时
    time.sleep(1.0)
    #SysLog.success('搜索漏洞', '成功搜索漏洞信息，查询到漏洞信息总数={}'.format(len(item_list)))
    return app_ok_p({'total': total, 'count': len(item_list), 'items': item_list})


def add(request):
    # firmware_id = req_post_param(request, "firmware_id")
    title = req_post_param(request, "title")
    author = req_post_param(request, "author")
    type = req_post_param(request, "type")
    platform = req_post_param(request, "platform")

    # 获取可用的firmware_id，内部检查取值范围和是否冲突（firmware_id需要唯一）
    firmware_id = firmware_db.get_suggest_firmware_id(None)

    # with utils.sys.config.g_mongo_client.start_session(causal_consistency=True) as session:
    #     """事物必须在session下执行,with保证了session的正常关闭"""
    # with session.start_transaction():
    #     """一旦出现异常会自动调用session.abort_transaction()"""
    # 获取各字段的索引号，如果是新值，则添加一条新索引，并返回新的id号
    author_id = firmware_db.fetch_field_id('author', author)
    type_id = firmware_db.fetch_field_id('type', type)
    platform_id = firmware_db.fetch_field_id('platform', platform)

    # 组装漏洞信息，并添加
    item = {'description': [firmware_id, title], 'date_published': SysUtils.get_now_time().strftime('%Y-%m-%d'),
            'verified': 0, 'port': 0, 'customized': 1,
            'author': {'id': author_id, 'name': author}, 'type': {'id': type_id, 'name': type},
            'platform': {'id': platform_id, 'platform': platform}, 'firmware_id': firmware_id}
    result = firmware_db.add(item)

    # 为性能测试中降低CPU使用率，小段延时
    time.sleep(1.0)

    # 本版本不检查成功与否
    #SysLog.success('新建漏洞', '成功添加漏洞信息，漏洞ID={}'.format(firmware_id))
    return app_ok_p({'firmware_id': firmware_id, 'customized': 1, 'date_published': item['date_published']})


def update(request):
    firmware_id = req_post_param(request, "firmware_id")
    title = req_post_param(request, "title")
    author = req_post_param(request, "author")
    type = req_post_param(request, "type")
    platform = req_post_param(request, "platform")

    # 只有定制的漏洞信息才能进行更新操作
    if not firmware_db.custom_firmware_id(firmware_id):
        #SysLog.fail('更新漏洞', '更新漏洞（ID={}）失败，只有定制的漏洞信息才能进行更新操作。'.format(firmware_id))
        return firmware_db.err_not_custom()

    # firmware_id不存在，表示没有可以更新的漏洞信息条目
    if not firmware_db.exist_firmware_id(firmware_id):
        #SysLog.fail('更新漏洞', '更新漏洞失败，该漏洞（ID={}）不存在。'.format(firmware_id))
        return app_err(Error.firmware_id_NOT_FOUND)

    # 获取各字段的索引号，如果是新值，则添加一条新索引，并返回新的id号
    author_id = firmware_db.fetch_field_id('author', author)
    type_id = firmware_db.fetch_field_id('type', type)
    platform_id = firmware_db.fetch_field_id('platform', platform)

    # 组装漏洞信息，并更新
    item = {'description': [firmware_id, title], 'author': {'id': author_id, 'name': author},
            'type': {'id': type_id, 'name': type}, 'platform': {'id': platform_id, 'platform': platform}}
    result = firmware_db.update(firmware_id, item)
    # 本版本不检查成功与否
    #SysLog.success('更新漏洞', '成功更新漏洞信息，漏洞ID={}'.format(firmware_id))
    return app_ok()


def delete(request):
    firmware_id = req_get_param(request, "firmware_id")
    if not firmware_db.custom_firmware_id(firmware_id):
        #SysLog.fail('删除漏洞', '删除漏洞（ID={}）失败，只有定制的漏洞信息才能进行删除操作。'.format(firmware_id))
        return firmware_db.err_not_custom()

    # firmware_id不存在，表示没有可以删除的漏洞信息条目
    if not firmware_db.exist_firmware_id(firmware_id):
        #SysLog.fail('删除漏洞', '删除漏洞失败，该漏洞（ID={}）不存在。'.format(firmware_id))
        return app_err(Error.firmware_id_NOT_FOUND)
    result = firmware_db.delete(firmware_id)

    # 本版本不检查成功与否
    #SysLog.success('删除漏洞', '成功删除漏洞信息，漏洞ID={}'.format(firmware_id))
    return app_ok()


def query_type(request):
    return app_ok_p(firmware_db.query_type())


def query_platform(request):
    return app_ok_p(firmware_db.query_platform())


def poc_query(request):
    offset = req_get_param_int(request, 'offset')
    count = req_get_param_int(request, 'count')

    # 获取信息总数
    total = firmware_pocs.count()
    # 指定偏移量越界，则报错
    if offset >= total:
        return app_err_p(Error.NO_MORE_DATA, {'total': total, 'count': 0})

    # 读取利用方法数据
    docs = firmware_pocs.query(offset, count)
    #SysLog.success('查询POC', '成功查询漏洞的POC，总数={}'.format(len(docs)))
    return app_ok_p({'total': total, 'count': len(docs), 'items': docs})

# 1.3 根据指定ID读取固件
def poc_fetch(request):
    firmware_id = req_get_param(request, 'firmware_id')
    # doc = firmware_db.fetch(firmware_id)
    poc = firmware_pocs.fetch(firmware_id)
    if poc is None:
        return sys_app_err('ERROR_FWPOC_NOT_FOUND')
    print(poc['aliases'])
    # print(poc['firmware_path'])
    # print(poc['length'])
    # print(poc['filelist'])
    filepath = poc['firmware_path']
    filename = poc['filelist']
    length = poc['length']

    #SysLog.success('提取POC', '成功提取漏洞的POC（漏洞ID={}）'.format(firmware_id))
    # doc['poc'] = poc

    # 将解压缩后的固件文件信息存入mongodb firmware_info
    item = {'fw_info': {'filepath': filepath, 'filename': filename, 'length': length}}
    firmware_db.update(firmware_id, item)

    return sys_app_ok_p(poc)


def poc_add(request):
    firmware_id = req_post_param(request, 'firmware_id')
    alias = req_post_param(request, 'alias')
    content = req_post_param(request, 'content')
    # 这三个参数都是POC的基本参数，不能为空
    if StrUtils.is_blank(firmware_id) or StrUtils.is_blank(alias) or StrUtils.is_blank(content):
        return app_err(Error.INVALID_REQ_PARAM)

    # 只有定制漏洞才能添加POC
    if not firmware_db.custom_firmware_id(firmware_id):
        #SysLog.fail('添加POC', '添加POC失败（漏洞ID={}）'.format(firmware_id))
        return firmware_db.err_not_custom()

    # firmware_id不存在，表示没有可以添加POC的漏洞信息条目
    if not firmware_db.exist_firmware_id(firmware_id):
        #SysLog.fail('添加POC', '添加POC失败（漏洞ID={}）'.format(firmware_id))
        return app_err(Error.firmware_id_NOT_FOUND)

    firmware_pocs.add(firmware_id, alias, content)
    #SysLog.success('添加POC', '成功添加漏洞的POC（漏洞ID={}）'.format(firmware_id))
    return app_ok()


def poc_update(request):
    firmware_id = req_post_param(request, 'firmware_id')
    alias = req_post_param(request, 'alias')
    content = req_post_param(request, 'content')
    # 这三个参数都是POC的基本参数，不能为空
    if StrUtils.is_blank(firmware_id) or StrUtils.is_blank(alias) or StrUtils.is_blank(content):
        return app_err(Error.INVALID_REQ_PARAM)

    # 只有定制漏洞才能添加POC
    if not firmware_db.custom_firmware_id(firmware_id):
        #SysLog.fail('更新POC', '更新POC失败（漏洞ID={}）'.format(firmware_id))
        return firmware_db.err_not_custom()

    # firmware_id不存在，表示没有可以添加POC的漏洞信息条目
    if not firmware_db.exist_firmware_id(firmware_id):
        #SysLog.fail('更新POC', '更新POC失败（漏洞ID={}）'.format(firmware_id))
        return app_err(Error.firmware_id_NOT_FOUND)

    # 更新POC
    firmware_pocs.update(firmware_id, alias, content)
    #SysLog.success('更新POC', '成功更新漏洞的POC（漏洞ID={}）'.format(firmware_id))
    return app_ok()


def poc_delete(request):
    firmware_id = req_get_param(request, 'firmware_id')
    if StrUtils.is_blank(firmware_id):
        return app_err(Error.INVALID_REQ_PARAM)

    # 删除POC
    if not firmware_pocs.delete(firmware_id):
        #SysLog.fail('删除POC', '删除POC失败（漏洞ID={}）'.format(firmware_id))
        return app_err(Error.EDB_POC_NOT_FOUND)

    #SysLog.success('删除POC', '成功删除漏洞的POC（漏洞ID={}）'.format(firmware_id))
    return app_ok()


def poc_search(request):
    offset = req_get_param_int(request, 'offset')
    count = req_get_param_int(request, 'count')
    value = req_get_param(request, 'value')

    # 查找利用信息
    result_cursor = firmware_db.search(value)
    item_list = list(result_cursor)

    # 获取信息总数，并判断指定偏移量是否越界
    total = len(item_list)
    if total == 0 or offset >= total:
        return app_err_p(Error.NO_MORE_DATA, {'total': total, 'count': 0})

    # 读取指定位置和数量的利用信息
    if count > total - offset:
        count = total - offset
    item_list = item_list[offset: offset + count]

    # 查询poc信息，添加到漏洞信息中
    # poc_list = []
    for item in item_list:
        poc = firmware_pocs.fetch_no_content(item['firmware_id'])
        item['poc'] = poc
        # poc_list.append(poc)
    #SysLog.success('搜索POC', '成功搜索POC文件，总数={}'.format(len(item_list)))
    return sys_app_ok_p({'total': total, 'count': len(item_list), 'items': item_list})


def poc_download(request):
    firmware_id = req_get_param(request, 'firmware_id')
    item = firmware_pocs.fetch(firmware_id)
    if item is None:
        return sys_app_err('ERROR_FWPOC_NOT_FOUND')

    file_name = item['aliases']
    # 对文本类型的文件名称增加txt后缀
    download_name = SysUtils.add_plain_text_file_suffix(file_name)
    # 设置响应内容的文件下载参数
    response = HttpResponse(item['content'], content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment;filename="%s"' % (urlquote(download_name))
    #SysLog.success('下载POC', '成功下载POC文件，漏洞ID={}'.format(firmware_id))
    return response


def max_id(request):
    max_id = firmware_db.max_firmware_id()
    return app_ok_p({'max_id': max_id})


def get_firmware(url_firmware, savepath):

    try:
        # self.makedir('firmware')

        # 获取网页的源代码
        # html = urllib.request.urlopen(self.base_url + str(page) + '.html')
        html = urllib.request.urlopen(url_firmware)
        content = html.read().decode('utf8')
        html.close()

        reg = r'<li class="rom_list"><a href="(.*)">(.*)</a>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
        reg = re.compile(reg)
        urls = re.findall(reg, content)
        for url in urls:
            # print(url[0])
            # print(url[1])
            # http://www.luyoudashi.com/roms/romlist-m1823.html
                           # a href = "/roms/romlist-m1823.html"
            urlsub = 'http://www.luyoudashi.com' + url[0]
            # urlsub = url_firmware + url[0]
            html = urllib.request.urlopen(urlsub)
            content1 = html.read().decode('utf8')
            html.close()

            soup = BeautifulSoup(content1, "html.parser")
            ul = soup.find('ul', class_="rom_list_list")
            ul = str(ul)
            reg1 = r'<li><span>(.*)</span><a href="(.*)">(.*)</a>(.*)</li>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
            reg1 = re.compile(reg1)
            targets = re.findall(reg1, ul)

            # for ul in soup.find_all("<li><span>[.*]</span>"):
            for ul in targets:
                # print(ul[0])
                # print(ul[1])
                # print(ul[2])
                # print(ul[3])

                urldownload = 'http://www.luyoudashi.com' + ul[1]
                html = urllib.request.urlopen(urldownload)
                content2 = html.read().decode('utf8')
                html.close()

                soup = BeautifulSoup(content2, "html.parser")
                rom_info_down = soup.find('div', class_="rom_info_down")
                print(rom_info_down)

                rom_info_data = soup.find('div', class_="rom_info_data")
                print(rom_info_data)

                # firmware_manufacturer = models.CharField(max_length=200)    #固件厂商
                # application_mode = models.CharField(max_length=128)         #适用机型
                # firmware_version = models.CharField(max_length=16)          #固件版本
                # firmware_size = models.CharField(max_length=8)              #文件大小
                # pub_date = models.DateTimeField('date published')           #发布日期
                # firmware_file_path = models.CharField(max_length=255)       #本地存放路径
                # 组装固件信息，并添加
                rom_info_data = str(rom_info_data)
                reg = r'<p>固件厂商：(.*)</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                # reg = r'<p>固件厂商：(.*)[官方固件]</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                v = re.findall(reg, rom_info_data)
                if v.__len__() > 0:
                    firmware_manufacturer = v[0]
                else:
                    firmware_manufacturer = ""

                reg = r'<p>适用机型：(.*)</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                v = re.findall(reg, rom_info_data)
                application_mode = v[0]

                reg = r'<p>固件版本：(.*)</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                v = re.findall(reg, rom_info_data)
                firmware_version = v[0]

                reg = r'<p>文件大小：(.*)</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                v = re.findall(reg, rom_info_data)
                firmware_size = v[0]

                reg = r'<p>发布日期：(.*)</p>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                v = re.findall(reg, rom_info_data)
                pub_date = v[0]

                rom_info_down = str(rom_info_down)
                reg = r'<a class="romdown" href="(.*)">立即下载固件</a>'  # 根据网站样式匹配的正则：(.* )可以匹配所有东西，加括号为我们需要的
                reg = re.compile(reg)
                urls = re.findall(reg, rom_info_down)
                print(urls[0])


                def download(url, firmware_id, item, savepath='./'):
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
                        print("\rdownloading: %5.1f%%" % (a * b * 100.0 / c), end="")

                    filename = os.path.basename(url)
                    # 判断文件是否存在，如果不存在则下载
                    if not os.path.isfile(os.path.join(savepath, filename)):
                        print('Downloading data from %s' % url)
                        urlretrieve(url, os.path.join(savepath, filename), reporthook=reporthook)

                        # #uncompress
                        # file_list = filename.split('.')
                        # print(file_list[file_list.__len__() - 1])
                        # if str(file_list[file_list.__len__() - 1]) == 'zip':
                        #     # zipfile解压
                        #     filename = filename.replace(".zip", ".rar")
                        #     print(filename)
                        #     print(zipfile.is_zipfile(filename))
                        #
                        #     rf = rarfile.RarFile(filename)    # 待解压文件
                        #     rf.extractall()              # 解压指定文件路径
                        #
                        #     z = zipfile.ZipFile(filename, 'r')
                        #     z.extractall(path=r"C:\Users\Administrator\Desktop")
                        #     z.close()
                        # else:
                        #     print('\nunknow file type!')
                        #
                        # #read bin file saveto mongodb
                        # filename = 'C:/GIT/firmwareanalyze/fw_fetch/TP-Link/TL-WVR900Lv1_cn_1.0.1_[20161207-rel73368]_up.bin'

                        item['fw_file_name'] = filename
                        result = firmware_db.add(item)

                        with open(filename, 'rb') as myimage:
                            data = myimage.read()
                            id= firmware_pocs.add(firmware_id, filename, data)
                            print(id)

                        print('\nDownload finished!')
                    else:
                        print('File already exsits!')
                    # 获取文件大小
                    filesize = os.path.getsize(os.path.join(savepath, filename))
                    # 文件大小默认以Bytes计， 转换为Mb
                    print('File size = %.2f Mb' % (filesize / 1024 / 1024))
                    return filename


                firmware_id = firmware_db.get_suggest_firmware_id(None)
                # firmware_id = 0
                item = {'fw_manufacturer': firmware_manufacturer,
                        'application_mode': application_mode,
                        'fw_version': firmware_version,
                        'fw_size': firmware_size,
                        'pub_date': pub_date,
                        # 'fw_file_name': filename,
                        'firmware_id': firmware_id
                        }
                filename = download(urls[0], firmware_id, item)

                break #只下载一个固件 ，全部下载耗时且占用磁盘空间大
            break
    except Exception as e:
        print(e)


# 固件下载
def async_fwdownload(request):

    # 获取下载URL
    downloadurl = req_get_param(request, 'url')
    print(downloadurl)

    # 启动下载任务
    task = MyTask(_proc_func_download, (downloadurl, settings.FW_PATH, ))
    task_id = task.get_task_id()

    # 返回响应：任务初始化的信息
    return sys_app_ok_p(MyTask.fetch_exec_info(task_id))


def _proc_func_download(downloadurl, g_fw_save_path, task_id):
    # 检查本地保存路径
    if os.path.isdir(g_fw_save_path):
        pass
    else:
        os.mkdir(g_fw_save_path)

    # 执行下载操作
    ret_download_info, fwfilename ,file_list = Mydownload.fwdownload(downloadurl, g_fw_save_path, task_id)
    print(ret_download_info, fwfilename)

    # 保存到mongodb
    # fwfilename = "C:\\GIT\\firmware_analyze_serv\\firmware\\CF-EW71-V2.6.0.zip"
    save_mongodb(g_fw_save_path, fwfilename, ret_download_info, task_id)

    # 保存下载任务到mongodb
    task_item = {
        'task_id': task_id,
        'type': 'download',
        'time': datetime.datetime.now(),
        'percentage': '100',
        'status': ret_download_info
    }
    firmware_db.task_update(task_id, task_item)

    # websocket通知页面
    ws = MyWebsocket()
    ws.sendmsg(task_item)

def save_mongodb(fwpath, fwfilename):
    fw_coll = MongoDB(firmware_info_coll)

    firmware_id = fw_coll.get_suggest_firmware_id(None)
    # 保存固件到mongodb 集合
    item = {
        'firmware_id': firmware_id,
        'fw_file_name': fwfilename,
        'application_mode': '',
        'fw_manufacturer': ''
    }
    fw_coll.update_fw(firmware_id, item)

    # 保存到存储桶
    with open(fwpath + fwfilename, 'rb') as myimage:
        data = myimage.read()
        firmware_pocs.add(firmware_id, fwfilename, data)

    task_coll = MongoDB(task_info_coll)



def _proc_func_download_old(downloadurl, g_fw_path, task_id):

    print("run download")
    savepath = g_fw_path
    if os.path.isdir(savepath):
        pass
    else:
        os.mkdir(savepath)

    # 获取数据库固件ID
    firmware_id = firmware_db.get_suggest_firmware_id(None)
    item = {
        'firmware_id': firmware_id
            }

    #执行文件下载
    ret_download_info, fwfilename ,file_list = Mydownload.fwdownload(downloadurl, savepath, task_id)
    print(ret_download_info, fwfilename)

    # 保存固件到mongodb
    item['fw_file_name'] = fwfilename
    item['application_mode'] = file_list[0]
    item['fw_manufacturer'] = ''
    firmware_db.add(item)

    # 保存到存储桶
    pathfilename = savepath + "\\" + fwfilename
    with open(pathfilename, 'rb') as myimage:
        data = myimage.read()
        firmware_pocs.add(firmware_id, fwfilename, data)

    # 保存下载任务到mongodb
    task_item = {
        'task_id': task_id,
        'type': 'download',
        'time': datetime.datetime.now(),
        'percentage': '100',
        'status': ret_download_info
    }
    # firmware_db.task_add(task_item)
    firmware_db.task_update(task_id, task_item)

    # websocket通知页面
    ws = MyWebsocket()
    ws.sendmsg(task_item)

    return ret_download_info
