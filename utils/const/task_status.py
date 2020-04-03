

class TaskStatus:
    # 任务启动
    START = 0
    # 远程下载
    REMOTE_DOWNLOAD = 1
    # 客户端上传
    CLIENT_UPLOAD = 2
    # 原始包抽取
    PACK_EXTRACT = 3
    # 文件系统抽取
    FS_EXTRACT = 4
    # CFG 解析
    CFG_ANALYZE = 5
    # 未知状态
    UNKNOWN = 99
    # 任务完成
    COMPLETE = 100

