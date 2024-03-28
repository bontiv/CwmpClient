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
    def __init__(self, type, value = None) -> None:
        self.type = type
        self.value = value
        self.readable = True
        self.writable = True

    def set(self, value):
        self.value = value

    def get(self):
        return self.value

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if len(args) == 1:
            self.value = args[0]
        else:
            return self.value

    def __str__(self) -> str:
        return str(self.value)

class ROParameter (Parameter):  
    def __init__(self, type, value = None) -> None:
        super().__init__(type, value)
        self.readable = True
        self.writable = False

