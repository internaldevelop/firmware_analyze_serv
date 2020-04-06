# mongo存储桶操作
import utils.sys
from utils.gadget.general import SysUtils
from django.conf import settings

class MongoPocs:
    def __init__(self, pocs, FW_PATH):
        self.method_fs = pocs
        self.FW_PATH = FW_PATH

    def add(self, firmware_id, alias, content):
        type = SysUtils.parse_file_type(alias)
        # 更新POC到 GridFS 存储桶中
        # method_fs.put(content.encode(encoding="utf-8"), content_type=type, filename=firmware_id, aliases=[alias])
        self.method_fs.put(content, content_type=type, filename=firmware_id, aliases=[alias])
        return True

    def fetch(self, firmware_id):
        grid_out = self.method_fs.find_one({'filename': firmware_id})
        item = SysUtils.grid_out_to_dict(grid_out)
        if item is None:
            return None

        data = grid_out.read()
        print(item['aliases'])

        # save path file
        filename = self.FW_PATH + item['aliases']
        outf = open(filename, 'wb')  # 创建文件
        outf.write(data)
        outf.close()
        return item['aliases']

        # # uncompress zip
        # list = SysUtils.uncompress(filename, self.FW_PATH)
        #
        # # item['firmware_id'] = firmware_id
        # item['firmware_path'] = self.FW_PATH
        # item['filelist'] = list
        # return item