from utils.const.file_type import FileType

""" Deprecated """


class ImageFile:
    @staticmethod
    def image_file(sig_results):
        # PNG 文件
        if ImageFile._is_png_sig(sig_results):
            return FileType.PNG_FILE

        # BMP 文件
        if ImageFile._is_bmp_sig(sig_results):
            return FileType.BMP_FILE

        # JPG 文件
        if ImageFile._is_jpeg_sig(sig_results):
            return FileType.JPG_FILE

        # TIFF 文件
        if ImageFile._is_tiff_sig(sig_results):
            return FileType.TIFF_FILE

        # GIF 文件
        if ImageFile._is_gif_sig(sig_results):
            return FileType.GIF_FILE

        return FileType.OTHER_FILE

    @staticmethod
    def _is_png_sig(sig_results):
        # 首条 signature ，形如： PNG image, 328 x 124, 8-bit/color RGBA, non-interlaced
        return sig_results[0].description.find('PNG image') == 0

    @staticmethod
    def _is_bmp_sig(sig_results):
        # 首条 signature ，形如： PC bitmap, Windows 3.x format,, 431 x 249 x 24
        return sig_results[0].description.find('PC bitmap') == 0

    @staticmethod
    def _is_jpeg_sig(sig_results):
        # 首条 signature ，形如： JPEG image data, JFIF standard 1.01
        return sig_results[0].description.find('JPEG image data') == 0

    @staticmethod
    def _is_tiff_sig(sig_results):
        # 首条 signature ，形如： TIFF image data, little-endian offset of first image directory: 20906
        return sig_results[0].description.find('TIFF image data') == 0

    @staticmethod
    def _is_gif_sig(sig_results):
        # 首条 signature ，形如： GIF image data, version "89a", 431 x 249
        return sig_results[0].description.find('GIF image data') == 0
