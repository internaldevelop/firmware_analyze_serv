from utils.gadget.my_file import MyFile
from utils.gadget.strutil import StrUtils


class MyTree:

    # "bin": {
    #     "busybox": {
    #         "file_path": "/bin/busybox",
    #         "file_id": "da7e1f9b-4976-4cf6-a12d-b676e4eb86c4"
    #     },
    #     ...
    # }
    @staticmethod
    def file_path_insert_into_tree(tree_obj, file_path, file_id, component=None):
        # 从文件路径获取 folders_list, file_name
        folders_list, file_name = MyFile.file_path_to_folder_list(file_path)

        # 添加或遍历各级 folder 节点
        node_obj = tree_obj
        for index, folder in enumerate(folders_list):
            if node_obj.get(folder) is None:
                # 只有目录节点为空时，才添加目录节点
                node_obj[folder] = {}

            # 准备下一级节点设置
            node_obj = node_obj[folder]

        # 最后，添加叶子节点（含文件ID和文件路径信息）
        node_obj[file_name] = {'file_path': file_path, 'file_id': file_id, 'component': component}

    # tree_data = [ 节点数组
    #   {
    #       "title": "bin",
    #       "key": 'da7e1f9b-4976-4cf6-a12d-b676e4eb86c4'
    #       "file_path": '/bin/busybox'  文件节点才加 file_path
    #       "children": [节点数组]
    #   },
    #   {}, ... {}
    # ]
    @staticmethod
    def file_path_insert_into_antd_tree(tree_obj, file_path, file_id, component=None):
        # 从文件路径获取 folders_list, file_name
        folders_list, file_name = MyFile.file_path_to_folder_list(file_path)

        # if len(folders_list) == 0:
        #     nodes_list = tree_obj
        #     nodes_list.append({'title': file_name, 'key': file_id, 'file_path': file_path, 'children': []})

        nodes_list = tree_obj
        if len(folders_list) > 0:
            # 添加或遍历各级 folder 节点
            for index, folder in enumerate(folders_list):
                found = False
                for node in nodes_list:
                    if node['title'] == folder:
                        # 找到 folder 节点后，结束查找，设置标志
                        found = True
                        break

                # 没有找到 folder 节点，添加新节点
                if not found:
                    # folder 节点不设置 file_path
                    node = {'title': folder, 'key': StrUtils.uuid_str(), 'file_path': '', 'children': []}
                    nodes_list.append(node)

                # 在找到或新建的节点下，准备下一个节点定位，或者添加文件节点
                nodes_list = node['children']

        # 添加文件节点
        node = {'title': file_name, 'key': file_id, 'file_path': file_path, 'component': component, 'children': []}
        nodes_list.append(node)
        # pass
