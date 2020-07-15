import json
import urllib.parse
import urllib.request

from utils.sys.config import g_java_service_ip


def task_feedback(task_uuid, task_status):

    try:
        url = "http://" + g_java_service_ip + ":10901/firmware/setdata"

        data = json.dumps(task_status)

        # 定义请求数据，并且对数据进行赋值
        values = {}
        values['task_uuid'] = task_uuid
        values['datas'] = data

        # # 对请求数据进行编码
        data = urllib.parse.urlencode(values)
        print(type(data))  # 打印<class 'str'>
        print(data)  # 打印status=hq&token=C6AD7DAA24BAA29AE14465DDC0E48ED9

        # 将数据与url进行拼接
        req = url + '?' + data
        # 打开请求
        response = urllib.request.urlopen(req)
        # print(response.code)
    except Exception as e:
         print("task_feedback error:", e)

    # try:
    #     import thread
    # except ImportError:
    #     import _thread as thread
    # import time
    # import websocket
    #
    # try:
    #     url = "ws://" + g_java_service_ip + ":10901/websocket/asset_info"
    #     data = json.dumps(task_status)
    #     # ws = websocket.create_connection("ws://127.0.0.1:8080/")
    #     ws = websocket.create_connection(url)
    #     ret = ws.send(data)
    #     print(data)
    #     print(ret)
    #
    # except Exception as e:
    #     print("task_feedback error:", e)

    # while True:
    #     data = ws.recv()
    #     print(data)
