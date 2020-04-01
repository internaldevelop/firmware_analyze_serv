import os

from urllib.request import urlretrieve
from utils.task import MyTask


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

            def translate_percent(percentage):
                if percentage == 0.0:
                    return 0.0
                elif percentage == 100.0:
                    return 100.0
                else:
                    return int(percentage / 5) * 5 + 5

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
                # 只在运行百分比变化时才更新任务状态
                new_percentage = translate_percent(percentage)
                exec_info = MyTask.fetch_exec_info(task_id)
                old_percentage = exec_info['percentage']
                if new_percentage != old_percentage:
                    MyTask.save_exec_info(task_id, new_percentage)


            filename = os.path.basename(downloadurl)
            # 判断是否为合法下载文件名 .zip .bin .img .rar .exe ...
            filetype = 'zip,bin,img,rar,exe,trx'
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

            MyTask.save_exec_info(task_id, 100.0, {'download': result})

            return 'ERROR_OK', filename, file_list

        except Exception as e:
            print(e)
            MyTask.save_exec_info(task_id, 100.0, {'download': str(e)})
            return 'ERROR_EXCEPTION', e


