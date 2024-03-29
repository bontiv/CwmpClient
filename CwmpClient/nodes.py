from typing import Any
import logging
SOAPNS = 'http://schemas.xmlsoap.org/soap/envelope/'
CWMPNS = 'urn:dslforum-org:cwmp-1-0'
XSDNS = 'http://www.w3.org/2001/XMLSchema'
XSINS = 'http://www.w3.org/2001/XMLSchema-instance'

log = logging.getLogger()

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
        if self.setter is not None:
            self.setter(value)
        self.value = value

    def get(self):
        if callable(self.getter):
            return self.getter()
        return self.value

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if len(args) == 1:
            new_value = args[0]
            # Common type cast
            if self.type == int:
                new_value = int(new_value)
            elif self.type == bool:
                new_value = new_value if type(new_value) == bool else new_value == "1"
            elif self.type == float:
                new_value = float(new_value)
            self.set(new_value)
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
        value_type = value if type(value) == type else type(value)

        def setter(new_value):
            log.debug("SET %s for %s/%s", str(new_value), path, parameter)
            self.config.set(path, parameter, str(new_value))
            self.write()

        while len(path_parts) > 0:
            next_node = path_parts.pop(0)
            node = node[next_node]

        if not self.config.has_section(path):
            self.config.add_section(path)

        if parameter in self.config[path]:
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

class ParameterList:
    def __init__(self, config) -> None:
        self.config = config
        self.parameters = dict()

    def addPath(self, path: str) -> None:
        path_parts = path.split('.') if len(path) > 0 else []
        self._get_parameters(self.config, path_parts)

    def _get_parameters(self, currentNode : BaseNode, path: list[str], prefix: str = "") -> None:
        if isinstance(currentNode, Parameter):
            self.parameters.update({prefix: currentNode})
        elif len(path) == 0:
            self.parameters.update({(prefix + '.' if len(prefix) > 0 else '') + name: child for name, child in currentNode.childs.items()})
        else:
            node_name = path.pop(0)
            if len(node_name) == 0:
                self.parameters.update({prefix + '.' + name: child for name, child in currentNode.childs.items()})
            elif node_name == '*':
                for node_name in currentNode.childs:
                    self._get_parameters(currentNode[node_name], path, prefix + '.' + node_name if len(prefix) > 0 else node_name)
            else:
                self._get_parameters(currentNode[node_name], path, prefix + '.' + node_name if len(prefix) > 0 else node_name)

    def todom(self, document):
        raise NotImplementedError()

    def __repr__(self) -> str:
        return "ParameterList[ %s ]" % ", ".join(" = ".join([key, str(value)]) for key, value in self.parameters.items())

class ParameterListValue(ParameterList):
    def todom(self, document):
        pl = document.createElement('ParameterList')
        pl.setAttributeNS(SOAPNS, 'soap:arrayType', "cwmp:ParameterValueStruct[%d]" % len(self.parameters))
        for key, value in self.parameters.items():
            pis = document.createElement('ParameterValueStruct')
            name = document.createElement('Name')
            name.appendChild(document.createTextNode( key.lstrip(".") ))
            pis.appendChild(name)
            value_node = document.createElement('Value')
            if value.type == bool:
                value_node.appendChild(document.createTextNode("1" if value() else "0"))
                value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:boolean')
            elif value() is None:
                value_node.appendChild(document.createTextNode("null"))
            else:
                value_node.appendChild(document.createTextNode(str(value())))
                if value.type == int:
                    value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:int')
                elif value.type == float:
                    value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:decimal')
                elif value.type == str:
                    value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:string')
                elif type(value.type) == str:
                    value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:' + value.type)
                else:
                    log.error("Unknown type conversion from %s to XML", value.type)
                    value_node.setAttributeNS(XSINS, 'xsi:type', 'xsd:string')

            pis.appendChild(value_node)
            pl.appendChild(pis)
        return pl
    
class ParameterListName(ParameterList):
    def todom(self, document):
        pl = document.createElement('ParameterList')
        pl.setAttributeNS(SOAPNS, 'soap:arrayType', "cwmp:ParameterInfoStruct[%d]" % len(self.parameters))
        for key, value in self.parameters.items():
            pis = document.createElement('ParameterInfoStruct')
            name = document.createElement('Name')
            name.appendChild(document.createTextNode( key if isinstance(value, Parameter) else key + "." ))
            pis.appendChild(name)
            writable = document.createElement('Writable')
            writable.appendChild(document.createTextNode("1" if value.writable else "0"))
            pis.appendChild(writable)
            pl.appendChild(pis)
        return pl
