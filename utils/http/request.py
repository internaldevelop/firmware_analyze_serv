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
    def func(request, protocol='GET'):
        dict = ReqParams._params_dict(request, protocol)

        file_id = dict.get('file_id')
        func_addr_hex = dict.get('func_addr')
        func_addr = int(func_addr_hex, 16)
        return file_id, func_addr
