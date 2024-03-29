from CwmpClient.nodes import ConfigFileParameter
import asyncio, logging, binascii, random, socket
from CwmpClient.app import App

log = logging.getLogger()
STUN_BIND_REQUEST_MSG = '0001'

def b2a_hexstr(abytes):
    return binascii.b2a_hex(abytes).decode("ascii")

class CwmpUdpListenerProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        log.info("Receiving CWMP UDP %s:%d = %s", addr[0], addr[1], b2a_hexstr(data))


class StunClientProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        super().__init__()
        self.tranid = ""

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        return super().connection_made(transport)

    def datagram_received(self, data, addr):
        log.info("Receiving UDP %s:%d = %s", addr[0], addr[1], b2a_hexstr(data))
        log.debug('Infos from %s', addr)
        msgtype = b2a_hexstr(data[0:2])
        if msgtype == '0101': # Response type
            log.debug('Get STUN packet')
            if self.tranid.upper() != b2a_hexstr(data[4:20]).upper():
                log.error('Cookie not valid. This packet cannot be executed')
                return

            len_message = int(b2a_hexstr(data[2:4]), 16)
            len_remain = len_message
            ptr = 20
            while len_remain:
                attr_type = b2a_hexstr(data[ptr:(ptr + 2)])
                attr_len = int(b2a_hexstr(data[(ptr + 2):(ptr + 4)]), 16)
                if attr_type == '0001':
                    #Mapped address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get mapped address: %s, %d", ip, port)
                    self.remote_addr.set_result((ip, port))

                elif attr_type == '0004':
                    #source address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get source address: %s, %d", ip, port)

                elif attr_type == '0005':
                    #Changed address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get changed address: %s, %d", ip, port)

                ptr = ptr + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)


    async def get_public_addr(self, transport: asyncio.DatagramTransport, remote_addr: tuple[str, int], send_data = ""):
        self.tranid = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
        str_len = "%#04d" % (len(send_data) / 2)
        str_data = ''.join([STUN_BIND_REQUEST_MSG, str_len, self.tranid, send_data])
        data = binascii.a2b_hex(str_data)
        self.remote_addr = asyncio.Future()

        for i in range(5):
            transport.sendto(data, remote_addr)
            await asyncio.wait_for(self.remote_addr, 1)
            if self.remote_addr.done():
                break
            await asyncio.sleep(1)

        if self.remote_addr.done():
            return self.remote_addr.result()
        else:
            raise Exception('Cannot get public address by STUN')


class STUN_client:
    def __init__(self, app: App):
        self.app = app
        self.protocol = None
        self.transport = None
        self.sturn_addr = None
        self.keepalive: asyncio.Task = None

    async def _keepalive(self):
        while True:
            await asyncio.sleep(10)
            await self.protocol.get_public_addr(self.transport, self.sturn_addr[0][4])

    async def load(self):
        loop = asyncio.get_event_loop()
        if self.app.root['Device']['ManagementServer']['STUNEnable']() == True:
            server = self.app.root['Device']['ManagementServer']['STUNServerAddress']()
            port = self.app.root['Device']['ManagementServer']['STUNServerPort']()
            self.sturn_addr = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_UDP)
            print(self.sturn_addr)
            
            self.transport, self.protocol = await loop.create_datagram_endpoint(lambda : StunClientProtocol(), remote_addr=self.sturn_addr[0][4], family=socket.AF_INET)
            log.info("Start STUN discovery at: %s:%d", server, port)
            
            public_address = await self.protocol.get_public_addr(self.transport, self.sturn_addr[0][4])
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

            if public_address[0] in local_ips:
                log.info("Not natted device.")
                self.app.root['Device']['ManagementServer']['NATDetected'](False)
            else:
                log.warn("Device behind NAT. Public IP: %s not in %s", public_address[0], ", ".join(local_ips))
                self.app.root['Device']['ManagementServer']['NATDetected'](True)
                self.app.root['Device']['ManagementServer']['UDPConnectionRequestAddress'](public_address[0] + ":" + str(public_address[1]))

            self.keepalive = asyncio.create_task(self._keepalive())

    async def unload(self):
        if self.keepalive != None:
            self.keepalive.cancel()
            await self.keepalive