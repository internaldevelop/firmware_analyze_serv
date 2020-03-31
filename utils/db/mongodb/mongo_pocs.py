# mongo存储桶操作
import utils.sys
from utils.gadget.general import SysUtils
from django.conf import settings

class MongoPocs:
    def __init__(self, pocs):
        self.method_fs = pocs

    def add(self, firmware_id, alias, content):
        type = SysUtils.parse_file_type(alias)
        # 更新POC到 GridFS 存储桶中
        # method_fs.put(content.encode(encoding="utf-8"), content_type=type, filename=firmware_id, aliases=[alias])
        self.method_fs.put(content, content_type=type, filename=firmware_id, aliases=[alias])
        return True