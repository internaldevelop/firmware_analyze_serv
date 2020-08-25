from django.urls import path

from . import views

# import sys
# sys.path.append('../../fw_analyze/my_views')
# # from ./fw_analyze/my_views import pack_view
# import pack_view

urlpatterns = [

    #
    # 组件源码：异步调用接口
    #
    # 组件源码查询
    path('async_funcs/list', views.list, name='async_com_list'),

    # 9.2 查询组件包信息
    path('info', views.info, name='com_info'),

    # 组件源码编译
    path('async_funcs/compile', views.compile, name='async_com_compile'),
    # 组件编译结果查询
    path('async_funcs/list_make', views.list_make, name='async_com_list_make'),

    # 9.5 组件源码查询_按名称查询
    path('async_funcs/list_name', views.list_name, name='async_com_list_name'),

    # 组件手动漏洞关联
    path('async_funcs/vuler_association', views.vuler_association, name='async_com_vuler_association'),

    # # 组件自动漏洞关联
    # path('async_funcs/auto_vuler_association', pack_view.vuler_association, name='async_com_vuler_association'),

    # 组件关联任务进度接口
    path('async_funcs/task_vuler_association', views.task_vuler_association, name='async_com_vuler_association'),

    path('test', views.test, name='async_test'),
    path('testcmd', views.testcmd, name='async_testcmd'),

    # 余弦相似度、倒排索引
    path('async_funcs/cosine_algorithm', views.cosine_algorithm, name='cosine_algorithm'),
    path('async_funcs/inverted', views.inverted, name='inverted'),
    path('async_funcs/get_inverted_data', views.get_inverted_data, name='get_inverted_data'),
    path('async_funcs/get_inverted_fw_data', views.get_inverted_fw_data, name='get_inverted_fw_data'),

]
