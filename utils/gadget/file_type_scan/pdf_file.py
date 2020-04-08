from utils.const.file_type import FileType


class PdfFile:
    @staticmethod
    def pdf_file(sig_results):
        return FileType.PDF_FILE if PdfFile._is_pdf_sig(sig_results) else FileType.OTHER_FILE

    @staticmethod
    def _is_pdf_sig(sig_results):
        # 首条 signature ，形如： PDF document, version: "1.7"
        return sig_results[0].description.find('PDF document') == 0
