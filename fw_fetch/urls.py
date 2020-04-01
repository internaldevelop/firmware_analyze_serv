from django.urls import path

from . import views
from . import old_views

urlpatterns = [
    path('', old_views.index, name='index'),

    path('test', old_views.test, name='firmware_test'),
    # 1.1 指定URL抓取固件 http://www.luyoudashi.com
    path('download', old_views.fwdownload, name='firmware_download'),
    path('downloadex', old_views.fwdownloadex, name='firmware_download'),
    # # 1.2 查询固件列表
    # path('list', old_views.list, name='firmware_list'),

    # 1.3 根据指定ID读取固件  将固件文件进行解压缩操作
    path('poc/fetch', old_views.poc_fetch, name='firmware_poc_fetch'),

    path('testws', old_views.testws, name='testws'),
    #
    # 固件获取：异步调用接口
    #

    # 固件下载
    path('async_funcs/download', views.async_fwdownload, name='async_fwdownload'),

    # 1.2 查询固件列表
    path('list', views.list, name='firmware_list'),

    # 1.3 根据指定ID读取固件  将固件文件进行解压缩操作,提取文件目录到数据库
    path('async_funcs/fetch', views.async_funcs_fetch, name='async_funcs_fetch'),

]