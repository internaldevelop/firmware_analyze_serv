import pymongo
from gridfs import GridFS

# edb采用标准数据库还是小数据库
# 1：标准数据库；2：小数据库；
# EDB_TYPE = 2
#
# mongo-db客户端
g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@172.16.60.5:27017/")
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@172.16.113.73:27017/")
# g_mongo_client = pymongo.MongoClient("mongodb://admin:123456@192.168.199.244:27017/")

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
# if EDB_TYPE == 1:
#     # 完整数据库
#     g_exploit_db = g_exploit_db_full
#     g_edb_info_col = g_edb_info_col_full
#     g_edb_method_fs = g_edb_method_fs_full
#     g_author_coll = g_author_coll_full
#     g_type_coll = g_type_coll_full
#     g_platform_coll = g_platform_coll_full
# elif EDB_TYPE == 2:
#     # 小数据库
#     g_exploit_db = g_exploit_db_tiny
#     g_edb_info_col = g_edb_info_col_tiny
#     g_edb_method_fs = g_edb_method_fs_tiny
#     g_author_coll = g_author_coll_tiny
#     g_type_coll = g_type_coll_tiny
#     g_platform_coll = g_platform_coll_tiny
# else:
#     # 默认用小数据库
#     g_exploit_db = g_exploit_db_tiny
#     g_edb_info_col = g_edb_info_col_tiny
#     g_edb_method_fs = g_edb_method_fs_tiny
#     g_author_coll = g_author_coll_tiny
#     g_type_coll = g_type_coll_tiny
#     g_platform_coll = g_platform_coll_tiny
