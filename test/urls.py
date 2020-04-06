from django.urls import path

from .views import test_zip_view
from .views import test_squash_view
from .views import test_pack_view
from .views import test_aux

urlpatterns = [
    # 测试压缩包文件信息
    path('zip_info', test_zip_view.test_zip_file, name='test_zip_file'),

    # 测试 squash fs
    path('squash', test_squash_view.test_squash_fs, name='test_squash_fs'),

    # 测试抽取 squash fs
    path('extract_squash', test_squash_view.test_extract_squash_fs, name='test_extract_squash_fs'),

    # 枚举 squash fs 镜像中的文件
    path('list_squash', test_squash_view.test_list_squash_fs, name='test_list_squash_fs'),

    # 生成 UUID
    path('uuid', test_aux.test_generate_uuid, name='test_generate_uuid'),

    # 日志开关测试
    path('log_switch', test_aux.test_log_switch, name='test_log_switch'),

    # 保存包文件
    path('save_pack', test_pack_view.test_save_pack, name='test_save_pack'),

    # 保存镜像文件
    path('save_image', test_pack_view.test_save_image, name='test_save_image'),

    # 包文件提取批处理
    path('pack_extract_bat', test_pack_view.test_pack_extract_bat, name='test_pack_extract_bat'),

    # 保存单个可执行文件
    path('add_single_exec', test_pack_view.test_add_single_exec, name='test_add_single_exec'),

    # 清空虚拟包及其文件
    path('clear_virtual_packs', test_pack_view.test_clear_virtual_packs, name='test_clear_virtual_packs'),

    # 清空实体包及其文件
    path('clear_real_packs', test_pack_view.test_clear_real_packs, name='test_clear_real_packs'),

    #
    # # 初步检验文件 -- 多用于测试
    # path('check_file', info_view.check_file, name='check_file'),
    #
    # # 系统配置重置为出厂参数
    # path('default_config', sys_config_view.reset_default_sys_config, name='reset_default_sys_config'),
    #
    # # 写入新的系统配置
    # path('write_config', sys_config_view.write_sys_config, name='write_sys_config'),
    #
    # # 读取系统配置
    # path('read_config', sys_config_view.read_sys_config, name='read_sys_config'),

]
