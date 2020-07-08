from django.urls import path

from . import views

urlpatterns = [

    #
    # 组件源码：异步调用接口
    #

    # 组件源码下载
    path('async_funcs/compile', views.compile, name='async_compile'),
    path('async_funcs/test', views.test, name='async_test'),
    path('async_funcs/testcmd', views.testcmd, name='async_testcmd'),

    # 余弦相似度、倒排索引
    path('async_funcs/cosine_algorithm', views.cosine_algorithm, name='cosine_algorithm'),
    path('async_funcs/inverted', views.inverted, name='inverted'),
    path('async_funcs/get_inverted_data', views.get_inverted_data, name='get_inverted_data'),
    path('async_funcs/get_inverted_fw_data', views.get_inverted_fw_data, name='get_inverted_fw_data'),

]
