from enum import Enum, unique
from common.utils.general import enum

err = [
    {'code': 0, 'msg': '成功'},
    {'code': 1002, 'msg': '系统内部异常'},
    {'code': 1003, 'msg': '未查询到数据'},
    {'code': 1004, 'msg': '请求参数错误'},
    {'code': 1005, 'msg': '账户已注册'},
    {'code': 1006, 'msg': '账户未找到'},
    {'code': 1007, 'msg': '账户密码校验失败'},
    {'code': 1008, 'msg': '账户密码已锁定'},
    {'code': 1009, 'msg': '创建账户失败'},
    {'code': 1010, 'msg': '参数越界'},
    {'code': 1011, 'msg': '找不到指定漏洞的POC'},
    {'code': 1012, 'msg': '查询失败'},
    {'code': 1013, 'msg': '漏洞信息ID号已存在'},
    {'code': 1014, 'msg': '找不到指定ID的漏洞信息'},
    {'code': 1015, 'msg': '漏洞信息ID号不符合要求'},
    {'code': 1016, 'msg': '操作只能适用于定制的漏洞信息（ID号不符合要求）'},
    {'code': 1017, 'msg': '未识别的文件下载类型'},
    {'code': 1018, 'msg': '没有找到指定的固件文件'},
    {'code': 1019, 'msg': '固件尚未进行函数调用流程的分析'},

    {'code': 9999, 'msg': '未知错误'},
]

Error = enum(
    'OK',
    'INTERNAL_EXCEPT',
    'NO_MORE_DATA',
    'INVALID_REQ_PARAM',
    'ACC_REGISTERED',
    'ACC_NOT_FOUND',
    'FAIL_VERIFY_PASSWORD',
    'PASSWORD_LOCKED',
    'FAIL_CREATE_ACC',
    'OUT_OF_BOUND',
    'EDB_POC_NOT_FOUND',
    'FAIL_QUERY',
    'EDB_ID_EXIST',
    'EDB_ID_NOT_FOUND',
    'INVALID_EDB_ID',
    'NEED_CUSTOM_EDB_ID',
    'UNKNOWN_FILE_TYPE',
    'FW_FILE_NOT_FOUND',
    'FW_FILE_NO_CFG_ANALYZE',
    'UNKNOWN',
)


# @unique
# class Error(Enum):
#     OK = 0
#     UNKNOWN = 1


def get_err(error):
    return err[error]
