from django.urls import path

from . import views

urlpatterns = [

    #
    # 组件源码：异步调用接口
    #
    # 组件源码查询
    path('async_funcs/list', views.list, name='async_com_list'),
    # 组件源码编译
    path('async_funcs/compile', views.compile, name='async_com_compile'),
    # 组件编译结果查询
    path('async_funcs/list_make', views.list_make, name='async_com_list_make'),

    path('async_funcs/test', views.test, name='async_test'),
    path('async_funcs/testcmd', views.testcmd, name='async_testcmd'),

]
