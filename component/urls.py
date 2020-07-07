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

]
