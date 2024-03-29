import logging
from .app import App

logging.basicConfig(level=logging.DEBUG)

myApp = App()
myApp.run()
