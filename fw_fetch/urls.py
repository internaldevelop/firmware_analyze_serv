from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),

    path('/test', views.test, name='firmware_test'),
    # 1.1 指定URL抓取固件 http://www.luyoudashi.com
    path('/download', views.fwdownload, name='firmware_download'),
    path('/downloadex', views.fwdownloadex, name='firmware_download'),
    # 1.2 查询固件列表
    path('/list', views.list, name='firmware_list'),
    # 1.3 根据指定ID读取固件
    path('/poc/fetch', views.poc_fetch, name='firmware_poc_fetch'),

]