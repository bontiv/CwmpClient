
import logging
import random
import socket
from CwmpClient.nodes import *
from asyncio import sleep
from .session import Tr69Inform
from .stunudp import STUN_client
log = logging.getLogger("TR-069")


async def loader(rootnode):
    log.debug('Load defaults parameters')
    config = ConfigFileParameter(rootnode, "tr069.ini")
    config.addItem('Device.ManagementServer.EnableCWMP', True)
    config.addItem('Device.ManagementServer.ConnectionRequestURL',
                   str, writable=False)
    config.addItem('Device.ManagementServer.ConnectionRequestPassword', str)
    config.addItem('Device.ManagementServer.ConnectionRequestUsername', str)
    config.addItem('Device.ManagementServer.URL', "http://acs.dites.team/")
    config.addItem('Device.ManagementServer.Password', str)
    config.addItem('Device.ManagementServer.Username', str)
    config.addItem('Device.ManagementServer.PeriodicInformEnable', False)
    config.addItem('Device.ManagementServer.PeriodicInformInterval', 300)
    config.addItem('Device.DeviceInfo.Manufacturer',
                   "Dites Telecom", writable=False)
    config.addItem('Device.DeviceInfo.ManufacturerOUI',
                   "FFFFFF", writable=False)
    config.addItem('Device.DeviceInfo.ProductClass', "DTBox1", writable=False)
    config.addItem('Device.DeviceInfo.SerialNumber', "0123456", writable=False)
    config.addItem('Device.DeviceInfo.ProvisioningCode', "")
    config.addItem('Device.DeviceInfo.SoftwareVersion',
                   "0.0.1", writable=False)
    config.addItem('Device.DeviceInfo.HardwareVersion',
                   "1.0.0", writable=False)
    config.addItem('Device.DeviceInfo.ParameterKey', "")
    config.addItem('Device.RootDataModelVersion', "2.15", writable=False)

    config.addItem('Device.ManagementServer.STUNEnable', True)
    config.addItem('Device.ManagementServer.NATDetected',
                   False, writable=False)
    config.addItem('Device.ManagementServer.STUNServerAddress',
                   "stun.l.google.com")
    config.addItem('Device.ManagementServer.STUNUsername', "")
    config.addItem('Device.ManagementServer.STUNPassword', "")
    config.addItem('Device.ManagementServer.STUNServerPort', 19302)
    config.addItem(
        'Device.ManagementServer.UDPConnectionRequestAddress', "", writable=False)
    config.write()


async def start(app):
    """
    Start TR69 Client. Send Boot event and start interval
    """
    import sys

    # First start STUN task
    stun = STUN_client(app)
    await stun.load()

    app.root['Device']['ManagementServer']['ConnectionRequestURL']('http://%s:%d/%s' % (
        socket.gethostbyname_ex(socket.gethostname())[2][0],
        7547,
        "".join([random.choice(
            "acbdefghijhlmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXIZ0123456789") for i in range(32)])
    ))

    events = ['1 BOOT']
    if len(sys.argv) > 1:
        events.append(sys.argv[1])
    req = Tr69Inform(app, *events)
    await req.run()

    while app.root['Device']['ManagementServer']['PeriodicInformEnable']():
        await sleep(app.root['Device']['ManagementServer']['PeriodicInformInterval']())
        await Tr69Inform(app, '2 PERIODIC').run()

    await stun.unload()
    print("End session")
