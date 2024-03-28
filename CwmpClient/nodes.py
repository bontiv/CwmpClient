from typing import Any


class BaseNode:
    def __init__(self) -> None:
        self.childs = dict()
        self.parent = None
        self.writable = False

    def __iter__(self):
        return self.childs.__iter__()

    def __getitem__(self, item):
        if item not in self.childs:
            self.childs[item] = BaseNode()
        return self.childs[item]

    def __setitem__(self, item, value):
        self.childs[item] = value

class Parameter:
    def __init__(self, type, value = None, writable = True, readable = True, setter = None, getter = None) -> None:
        self.type = type
        self.value = value
        self.readable = readable
        self.writable = writable
        self.setter = setter
        self.getter = getter

    def set(self, value):
        if callable(self.setter):
            self.setter(value)
        self.value = value

    def get(self):
        if callable(self.getter):
            return self.getter()
        return self.value

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if len(args) == 1:
            self.set(args[0])
        else:
            return self.get()

    def __str__(self) -> str:
        return str(self.value)

class ConfigFileParameter:
    """ Helper class for Parameter with config file persistent storage """
    def __init__(self, root: BaseNode, filename: str) -> None:
        import configparser, os.path
        self.config = configparser.ConfigParser()
        self.root = root
        self.filename = filename

        if os.path.exists(filename):
            self.config.read(filename)

    def addItem(self, key: str, value: any, writable: bool = True) -> None:
        path, _, parameter = key.rpartition(".")

        path_parts = path.split(".")
        node = self.root

        def setter(value):
            self.config.set(path, parameter, value)
            self.write()

        while len(path_parts) > 0:
            next_node = path_parts.pop(0)
            node = node[next_node]

        if not self.config.has_section(path):
            self.config.add_section(path)

        if parameter in self.config[path]:
            value_type = value if type(value) == type else type(value)
            value = None
            if value_type == int:
                value = self.config.getint(path, parameter)
            elif value_type == bool:
                value = self.config.getboolean(path, parameter)
            elif value_type == float:
                value = self.config.getfloat(path, parameter)
            else:
                value = self.config.get(path, parameter)
            node[parameter] = Parameter(value_type, value, writable=writable, setter=setter)
        elif type(value) == type:
            node[parameter] = Parameter(value, writable=writable, setter=setter)
        else:
            node[parameter] = Parameter(type(value), value, writable=writable, setter=setter)
            self.config[path][parameter] = str(value)

    def write(self) -> None:
        with open(self.filename, 'w') as fp:
            self.config.write(fp)
