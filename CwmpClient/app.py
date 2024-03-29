import asyncio
from concurrent.futures import ThreadPoolExecutor
import importlib
import pkgutil

from CwmpClient.helpers import prettyprint
from CwmpClient.nodes import BaseNode
import CwmpClient.plugins

def iter_namespace(ns_pkg):
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

def exeption_hdlr(context):
    print('ERROR ' + context.message)

class App:
    def __init__(self) -> None:
        self.root = BaseNode()
        self.tpe = ThreadPoolExecutor()
        self.runner = asyncio.Runner(loop_factory=self.loop_factory)
        self.plugins = {
            name: importlib.import_module(name)
            for finder, name, ispkg
            in iter_namespace(CwmpClient.plugins)
        }

    async def exec_modules(self, method :str, *args, **kwargs) -> None:
        coros = [ getattr(self.plugins[mod], method)(*args, **kwargs) for mod in self.plugins if hasattr(self.plugins[mod], method) ]
        await asyncio.gather(*coros)

    def loop_factory(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_default_executor(self.tpe)
        loop.set_debug(True)
        loop.set_exception_handler(exeption_hdlr)
        return loop

    def run(self):
        self.runner.run(self.exec_modules('loader', self.root))
        prettyprint(self.root)
        self.runner.run(self.exec_modules('start', self))
