import pymongo
from gridfs import GridFS
from redis import StrictRedis

g_server_ip = "localhost"
g_java_service_ip = "localhost"
g_docker_service_ip = "localhost"

# g_server_ip = "192.168.43.72"
# g_java_service_ip = "192.168.43.214"
# g_docker_service_ip = "192.168.43.214"
g_java_service_ip = "172.16.113.44"
g_docker_service_ip = "172.16.113.44"

# g_java_service_ip = "192.168.1.100"
# g_docker_service_ip = "192.168.1.100"

# EUREKA 配置信息
# eureka_server
eureka_server_list = "http://" + g_java_service_ip + ":10100/eureka/"
# 本地服务
your_rest_server_host = g_server_ip
your_rest_server_port = 10112

g_eureka_client = ""

# ===========================================================================================
# 各服务地址

# Websocket 配置
g_ws_url = "ws://" + g_java_service_ip + ":10901/websocket/firmware"

# mongo-db客户端
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@" + g_docker_service_ip + ":27017/")
g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@" + g_docker_service_ip + ":27017/", connect=False)
print(g_mongo_client)
# redis 客户端
g_redis_client = StrictRedis(host=g_docker_service_ip, port=16379, db=0, password='123456')

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
