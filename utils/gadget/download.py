import os
from urllib.request import urlretrieve
from urllib.parse import urlparse

from utils.ftp.myftp import Xfer
from utils.task.my_task import MyTask


class Mydownload:

    @staticmethod
    def http_download(downloadurl, savepath, task_id, total_percentage=100):
        try:
            """
            download file from internet
            :param url: path to download from
            :param savepath: path to save files
            :return: None
            """

            def translate_percent(percentage):
                if percentage == 0.0:
                    return 0.0
                elif percentage == 100.0:
                    return 100.0
                else:
                    # return int(percentage / 5) * 5 + 5
                    return int(percentage / 5) * 5

            def reporthook(a, b, c):
                """
                显示下载进度
                :param a: 已经下载的数据块
                :param b: 数据块的大小
                :param c: 远程文件大小
                :return: None
                """
                # 实际下载百分比
                percentage = round(a * b * 100 / c, 1)
                percentage_total = round(a * b * total_percentage / c, 1)
                print("\rdownloading: %5.1f%%" % percentage, "    total downloading: %5.1f%%" % percentage_total,
                      end="")

                # # 总占比百分比
                # percentage = round(a * b * total_percentage / c, 1)
                # print("\rdownload_proc: %5.1f%%" % percentage, end="")

                # 只在运行百分比变化时才更新任务状态
                new_percentage = translate_percent(percentage_total)
                exec_info = MyTask.fetch_exec_info(task_id)
                old_percentage = -1
                if exec_info is not None:
                    old_percentage = exec_info['percentage']
                if new_percentage != old_percentage:
                    MyTask.save_exec_info(task_id, new_percentage)

            filename = os.path.basename(downloadurl)
            MyTask.save_exec_info(task_id, total_percentage, {'download': "固件下载、提取、入库操作完成"})

            # 判断是否为合法下载文件名 .zip .bin .img .rar .exe ...
            filetype = 'zip,bin,img,rar,exe,trx'
            file_list = filename.split('.')
            result = file_list[file_list.__len__() - 1] in filetype
            # print(result)
            if not result:
                return 'ERROR_FETCH_FILE_TYPE', {'filetype': file_list[file_list.__len__() - 1]}, None

            # 判断文件是否存在，如果不存在则下载
            if not os.path.isfile(os.path.join(savepath, filename)):
                print('Downloading data from %s' % downloadurl)
                # homepage = 'http://www.comfast.cn/uploadfile/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/OrangeOS-X86-V2.1.0_20170114.zip'
                # 'http://comfast.com.cn/upload/%E8%BD%AF%E4%BB%B6%E9%A9%B1%E5%8A%A8/%E5%9B%BA%E4%BB%B6/CF-AC101-V2.4.0.zip'
                'http://comfast.com.cn/upload/软件驱动/固件/CF-AC101-V2.4.0.zip'
                'http://www.comfast.cn/uploadfile/firmware/CF-AC101-V2.6.1.zip'
                # homepage = homepage.encode()
                print(downloadurl)

                result_urlretrieve = urlretrieve(downloadurl, os.path.join(savepath, filename), reporthook=reporthook)

                print('\nDownload finished!', result_urlretrieve)
            else:
                # todo 判断文件完整性，是否重新下载
                # result = urlretrieve(downloadurl, os.path.join(savepath, filename), reporthook=reporthook)
                print('File already exsits!')
            MyTask.save_exec_info(task_id, total_percentage, {'download': os.path.join(savepath, filename)})

            return 'ERROR_OK', filename, file_list

        except Exception as e:
            print(e)
            MyTask.save_exec_info(task_id, 100.0, {'download': str(e)})
            return 'ERROR_EXCEPTION', None, None

    @staticmethod
    def ftp_download(downloadurl, savepath, ftp_user, ftp_passwrod, task_id, total_percentage=100):
        # TODO 下载带子目录的文件时存在问题，如：ftp://172.16.113.26/huawei/S5720SI-V200R011C10SPC600.zip
        url, file_name = os.path.split(downloadurl)
        file_list = file_name.split('.')

        # 解析IP todo 域名解析IP
        _url = urlparse(downloadurl)
        hostname = _url.hostname
        # port = _url.port

        xfer = Xfer()
        xfer.setFtpParams(hostname, ftp_user, ftp_passwrod)
        xfer.initEnv()
        xfer.downloadFile(file_name, savepath)
        xfer.clearEnv()

        return 'ERROR_OK', file_name, file_list
