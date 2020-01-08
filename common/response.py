from common.utils.general import TimeEncoder

from django.http import HttpResponse
from .error_code import Error, get_err
import datetime
import json
from django.conf import settings

def app_resp(err, payload):
    now_time = datetime.datetime.now()
    response = get_err(err)
    response['timeStamp'] = now_time.strftime("%Y-%m-%d %H:%M:%S")
    response['payload'] = payload
    return HttpResponse(json.dumps(response, ensure_ascii=False, indent=4, cls=TimeEncoder))


def app_ok_p(payload):
    return app_resp(Error.OK, payload)


def app_ok():
    return app_resp(Error.OK, {})


def app_err_p(err, payload):
    return app_resp(err, payload)


def app_err(err):
    return app_resp(err, {})


def sys_get_err(err):
    try:
        for code in settings.SYS_CODE:
            if code['code'] == err:
                # return code['concept']
                return code

        return {'code': 9999, 'msg': '未知错误'}

    except Exception as e:
        print(e)

def sys_app_resp(err, payload):
    now_time = datetime.datetime.now()
    response = sys_get_err(err)
    response['timeStamp'] = now_time.strftime("%Y-%m-%d %H:%M:%S")
    response['payload'] = payload
    return HttpResponse(json.dumps(response, ensure_ascii=False, indent=4, cls=TimeEncoder))


def sys_app_ok_p(payload):
    return sys_app_resp('ERROR_OK', payload)


def sys_app_ok():
    return sys_app_resp('ERROR_OK', {})


def sys_app_err_p(err, payload):
    return sys_app_resp(err, payload)


def sys_app_err(err):
    return sys_app_resp(err, {})
