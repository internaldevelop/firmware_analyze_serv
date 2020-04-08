from utils.const.file_type import FileType

""" 
可明确判断的文件，通过签名中明确的 description 信息，判定是哪种文件类型
一般通过首条或末条签名的匹配即可判定
"""


class ExplicitFile:
    """
    第一项为需检查的签名结果的索引，0表示首条，-1表示末条
    第二项为特征字符串
    第三项为文件类型
    """
    _check_list = [
        # 首条 signature ，形如： PDF document, version: "1.7"
        [0, 'PDF document', FileType.PDF_FILE],
        # 首条 signature ，形如： PNG image, 328 x 124, 8-bit/color RGBA, non-interlaced
        [0, 'PNG image', FileType.PNG_FILE],
        # 首条 signature ，形如： PC bitmap, Windows 3.x format,, 431 x 249 x 24
        [0, 'PC bitmap', FileType.BMP_FILE],
        # 首条 signature ，形如： JPEG image data, JFIF standard 1.01
        [0, 'JPEG image data', FileType.JPG_FILE],
        # 首条 signature ，形如： TIFF image data, little-endian offset of first image directory: 20906
        [0, 'TIFF image data', FileType.TIFF_FILE],
        # 首条 signature ，形如： GIF image data, version "89a", 431 x 249
        [0, 'GIF image data', FileType.GIF_FILE],
        # 首条 signature ，形如： RAR archive data, version 4.x, first volume type: MAIN_HEAD
        [0, 'RAR archive data', FileType.RAR_FILE],
        # 首条 signature ，形如： 7-zip archive data, version 0.4
        [0, '7-zip archive data', FileType.Z7Z_FILE],
        # 首条 signature ，形如： POSIX tar archive, owner user name: "nttype"
        # 末条 signature ，形如： POSIX tar archive, owner user name: "eaders.18556/sparse-0.0"
        [0, 'POSIX tar archive', FileType.TAR_FILE],
        # 首条 signature ，形如： Executable script, shebang: "/bin/sh /etc/rc.common"
        [0, 'Executable script', FileType.SH_SCRIPT],
    ]

    @staticmethod
    def judge_type(sig_results):
        for check_item in ExplicitFile._check_list:
            index = check_item[0]
            feature = check_item[1]
            if sig_results[index].description.find(feature) == 0:
                return check_item[2]

        # 没有在 check_list 中找到匹配项，返回未知类型
        return FileType.OTHER_FILE
