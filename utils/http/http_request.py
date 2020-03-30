def req_get_param(request, param):
    return request.GET.get(param)


def req_get_param_int(request, param):
    data = req_get_param(request, param)
    return int(data)


def req_post_param_dict(request):
    return request.POST


def req_post_param(request, param):
    return request.POST.get(param)


def req_post_param_int(request, param):
    data = req_post_param(request, param)
    return int(data)
