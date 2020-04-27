import json
import urllib.parse
import urllib.request

def task_feedback(task_uuid, task_status):

    url = "http://127.0.0.1:10901/firmware/setdata"

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