import pymongo
from gridfs import GridFS
from redis import StrictRedis

# edb采用标准数据库还是小数据库
# 1：标准数据库；2：小数据库；
# EDB_TYPE = 2
#

# ===========================================================================================
# 各服务地址

# mongo-db客户端
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@172.16.60.5:27017/")
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@172.16.113.26:27017/")
g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@192.168.182.88:27017/")
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@192.168.199.244:27017/")

# redis 客户端
g_redis_client = StrictRedis(host='192.168.182.88', port=16379, db=0, password='123456')

# ===========================================================================================
# 全局引用、全局对象定义

# 系统管理数据库
g_sys_manage_db = g_mongo_client["system_manage"]
# 账户集合
g_accounts_col = g_sys_manage_db["accounts"]

# firmware 数据库
g_firmware_db_full = g_mongo_client["firmware_db"]
# firmware 集合  表
g_firmware_info_col_full = g_firmware_db_full["firmware_info"]
# 固件操作方法文件存储桶
g_firmware_method_fs_full = GridFS(g_firmware_db_full, collection='firmware_methods')

# CFG 分析结果集合
g_cfg_result_col = g_firmware_db_full["cfg_result"]

# author，type，platform 的信息集合
g_author_coll_full = g_firmware_db_full["firmware_author"]
g_type_coll_full = g_firmware_db_full["firmware_type"]
g_platform_coll_full = g_firmware_db_full["firmware_platform"]

g_firmware_db = g_firmware_db_full
g_firmware_info_col = g_firmware_info_col_full
g_firmware_method_fs = g_firmware_method_fs_full
g_author_coll = g_author_coll_full
g_type_coll = g_type_coll_full
g_platform_coll = g_platform_coll_full

g_firmware_filepath = ''
