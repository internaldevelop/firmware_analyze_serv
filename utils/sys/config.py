import pymongo
from gridfs import GridFS
from redis import StrictRedis

# edb采用标准数据库还是小数据库
# 1：标准数据库；2：小数据库；
# EDB_TYPE = 2
#


# EUREKA 配置信息
# eureka_server
eureka_server_list = "http://localhost:10100/eureka/"
# eureka_server_list = "http://172.16.60.5:10100/eureka/"
# eureka_server_list = "http://192.168.43.139:10100/eureka/"
# 本地服务
your_rest_server_host = "localhost"
your_rest_server_port = 10112

# ===========================================================================================
# 各服务地址

# Websocket 配置
g_ws_url = "ws://localhost:10901/websocket/asset_info"

# mongo-db客户端
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@172.16.60.5:27017/")
g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@192.168.43.214:27017/")
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@192.168.182.88:27017/")

# redis 客户端
g_redis_client = StrictRedis(host='192.168.43.214', port=16379, db=0, password='123456')
# g_redis_client = StrictRedis(host='192.168.182.88', port=16379, db=0, password='123456')

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

# 系统配置集合
g_sys_dict_coll = g_firmware_db_full["sys_dictionary"]
# CFG 分析结果集合
g_cfg_result_coll = g_firmware_db_full["cfg_result"]
# 函数分析结果集合
g_func_result_coll = g_firmware_db_full["func_result"]
# 日志集合
g_logs_coll = g_firmware_db_full["logs"]
# 固件文件记录集合
g_fw_files_coll = g_firmware_db_full["fw_files"]
# 固件文件存储桶集合
g_fw_files_storage = GridFS(g_firmware_db_full, collection='fw_files_storage')
# 固件包记录集合
g_pack_files_coll = g_firmware_db_full["pack_files"]
# 固件包存储桶集合
g_pack_files_storage = GridFS(g_firmware_db_full, collection='pack_files_storage')

# 任务表 下载、提取、分析
g_task_info_col_full = g_firmware_db_full["task_info"]

# author，type，platform 的信息集合
g_author_coll_full = g_firmware_db_full["firmware_author"]
g_type_coll_full = g_firmware_db_full["firmware_type"]
g_platform_coll_full = g_firmware_db_full["firmware_platform"]

g_firmware_db = g_firmware_db_full
g_firmware_info_col = g_firmware_info_col_full
g_task_info_col = g_task_info_col_full
g_firmware_method_fs = g_firmware_method_fs_full
g_author_coll = g_author_coll_full
g_type_coll = g_type_coll_full
g_platform_coll = g_platform_coll_full

g_firmware_filepath = ''
