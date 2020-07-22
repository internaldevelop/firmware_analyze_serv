class TaskType:
    # 远程下载固件包任务
    REMOTE_DOWNLOAD = 1
    # 客户端上传固件包任务
    CLIENT_UPLOAD = 2
    # 原始包抽取(binwalk)
    PACK_EXTRACT = 3
    # 提取文件系统
    FS_EXTRACT = 4
    # CFG 解析
    CFG_ANALYZE = 5
    # 清空固件包(单个或多个)
    REMOVE_FW_PACKS = 6
    # 验证可执行二进制文件
    VERIFY_EXEC_BIN = 7
    # 组件编译
    COMPONENT_COMPILE = 8
    # 组件漏洞关联
    COMPONENT_CHECK = 9
    # 倒排索引
    INVERTED = 10

    # 一般任务
    REGULAR = 99
    # 异常任务(未知任务)
    UNKNOWN = -1
