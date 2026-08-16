class Context:
    pass


class Star:
    def __init__(self, context):
        self.context = context


def register(name, author, description, version):
    def decorator(cls):
        cls.__plugin_registration__ = {
            "name": name,
            "author": author,
            "description": description,
            "version": version,
        }
        return cls

    return decorator
