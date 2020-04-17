import utils.sys.config

from utils.db.mongodb.cursor_result import CursorResult
from utils.gadget.general import SysUtils

# 基于文件的分析结果的缓存
file_cache_coll = utils.sys.config.g_firmware_db_full["file_cache"]
