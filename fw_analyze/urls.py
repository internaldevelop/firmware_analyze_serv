from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('decode/', views.binwalk_scan_signature, name='firmware_binwalk'),     # 固件文件头自动解码或解析
    path('arch/', views.binwalk_scan_opcodes, name='firmware_binwalk'),         # 架构识别
    path('extract/', views.binwalk_file_extract, name='firmware_binwalk'),      # 抽取文件
    path('test/', views.binwalk_file_test, name='firmware_binwalk'),            # 抽取文件

    path('convertcode/', views.angr_convert_code, name='angr_convert_code'),    # 转换成中间代码
    path('recognize/', views.angr_recognize, name='angr_recognize'),            # 函数识别

]