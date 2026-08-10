class AstrMessageEvent:
    def plain_result(self, text):
        return text


class _Group:
    def __init__(self, function):
        self.function = function

    def command(self, _name):
        def decorator(function):
            return function

        return decorator


class _PermissionType:
    ADMIN = "admin"


class _Filter:
    PermissionType = _PermissionType

    @staticmethod
    def command_group(_name):
        def decorator(function):
            return _Group(function)

        return decorator

    @staticmethod
    def permission_type(_permission):
        def decorator(function):
            return function

        return decorator


filter = _Filter()