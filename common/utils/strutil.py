
class StrUtils:
    @staticmethod
    def is_blank(str_input):
        return str_input is None or len(str_input) == 0

    @staticmethod
    def to_int(str_input, def_value):
        if StrUtils.is_blank(str_input) or not str_input.isdigit():
            value = def_value
        else:
            value = int(str_input)

        return value

