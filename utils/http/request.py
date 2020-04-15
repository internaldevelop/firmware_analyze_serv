class ReqParams:
    @staticmethod
    def _params_dict(request, protocol='GET'):
        if protocol == 'GET':
            return request.GET
        elif protocol == 'POST':
            return request.POST
        else:
            return request.GET

    @staticmethod
    def _tag_and_type(name):
        str_list = name.split('.')
        if len(str_list) >= 2:
            return str_list[0], str_list[1]
        elif len(str_list) == 1:
            return str_list[0], 'str'
        else:
            return 'unknown', 'str'

    @staticmethod
    def _transfer(data, type):
        try:
            if type == 'int':
                return int(data)
            elif type == 'hex':
                return int(data, 16)
        except ValueError as v_err:
            return 0
        except TypeError as t_err:
            return 0

        return data

    @staticmethod
    def one(request, name, protocol='GET'):
        # 获取参数列表
        dict = ReqParams._params_dict(request, protocol)

        # 解析参数类型
        tag, type = ReqParams._tag_and_type(name)

        # 获取参数值
        value = dict.get(tag)

        # 返回转换后的参数值
        return ReqParams._transfer(value, type)

    @staticmethod
    def many(request, names, protocol='GET'):
        # 获取参数列表
        dict = ReqParams._params_dict(request, protocol)

        values = []
        for name in names:
            # 解析参数类型
            tag, type = ReqParams._tag_and_type(name)
            # 获取参数值
            value = dict.get(tag)
            # 转换参数值为指定类型
            new_value = ReqParams._transfer(value, type)

            values.append(new_value)

        return values

    @staticmethod
    def func(request, protocol='GET'):
        dict = ReqParams._params_dict(request, protocol)

        file_id = dict.get('file_id')
        func_addr_hex = dict.get('func_addr')
        func_addr = int(func_addr_hex, 16)
        return file_id, func_addr
