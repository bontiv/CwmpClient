from CwmpClient.nodes import ConfigFileParameter
import asyncio
import logging
import binascii
import random
import socket
import typing
import enum
from CwmpClient.app import App

log = logging.getLogger()

StunResponse = typing.NewType(
    'StunResponse', typing.Dict[str, typing.Tuple[str, int]])


@enum.unique
class NAT_TYPE(enum.Enum):
    NAT_NONE = enum.auto()
    NAT_CONE = enum.auto()
    NAT_FULL = enum.auto()
    NAT_RESTRICTED = enum.auto()
    NAT_SYMETRIC = enum.auto()


@enum.unique
class STUN_CODE (enum.StrEnum):
    BIND_REQUEST = '0001'
    CAHNGE_REQUEST = '0003'


def b2a_hexstr(abytes):
    return binascii.b2a_hex(abytes).decode("ascii")


class CwmpUdpListenerProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        log.info("Receiving CWMP UDP %s:%d = %s",
                 addr[0], addr[1], b2a_hexstr(data))


class StunClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, client: 'STUN_client') -> None:
        super().__init__()
        self.client = client

    def datagram_received(self, data, addr):
        log.info("Receiving UDP %s:%d = %s",
                 addr[0], addr[1], b2a_hexstr(data))
        log.debug('Infos from %s', addr)
        result: StunResponse = {'source_addr': (
            None, None), 'remote_addr': (None, None), 'change_addr': (None, None)}
        msgtype = b2a_hexstr(data[0:2])
        if msgtype == '0101':  # Response type
            log.debug('Get STUN packet')
            if self.client.tranid.upper() != b2a_hexstr(data[4:20]).upper():
                log.error('Cookie not valid. This packet cannot be executed')
                return

            len_message = int(b2a_hexstr(data[2:4]), 16)
            len_remain = len_message
            ptr = 20
            while len_remain:
                attr_type = b2a_hexstr(data[ptr:(ptr + 2)])
                attr_len = int(b2a_hexstr(data[(ptr + 2):(ptr + 4)]), 16)
                if attr_type == '0001':
                    # Mapped address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get mapped address: %s, %d", ip, port)
                    result['remote_addr'] = (ip, port)

                elif attr_type == '0004':
                    # source address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get source address: %s, %d", ip, port)
                    result['source_addr'] = (ip, port)

                elif attr_type == '0005':
                    # Changed address
                    port = int(b2a_hexstr(data[ptr + 6:ptr + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(data[ptr + 8:ptr + 9]), 16)),
                        str(int(b2a_hexstr(data[ptr + 9:ptr + 10]), 16)),
                        str(int(b2a_hexstr(data[ptr + 10:ptr + 11]), 16)),
                        str(int(b2a_hexstr(data[ptr + 11:ptr + 12]), 16))
                    ])
                    log.debug("Get changed address: %s, %d", ip, port)
                    result['change_addr'] = (ip, port)

                ptr = ptr + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
        self.client._last_response.set_result(result)


class STUN_client:
    def __init__(self, app: App):
        self.app = app
        self.protocol = None
        self.transport = None
        self.keepalive: asyncio.Task = None
        self._last_response: asyncio.Future = None
        self.sturn_addr: typing.Tuple[str, int] = None

    async def _send_stun_request(self, remote_addr: typing.Tuple[str, int], send_data=""):
        self.tranid = ''.join(random.choice('0123456789ABCDEF')
                              for i in range(32))
        str_len = "%#04d" % (len(send_data) / 2)
        str_data = ''.join(
            [STUN_CODE.BIND_REQUEST, str_len, self.tranid, send_data])
        data = binascii.a2b_hex(str_data)
        self._last_response: asyncio.Future[StunResponse] = asyncio.Future()

        for i in range(5):
            self.transport.sendto(data, remote_addr)
            await asyncio.wait([self._last_response], timeout=1)
            if self._last_response.done():
                return self._last_response.result()
            log.debug('Retry %d', i)

        return None

    async def _get_public_addr(self, remote_addr: typing.Tuple[str, int] = None) -> typing.Tuple[NAT_TYPE, typing.Tuple[str, int]]:
        if remote_addr is None:
            remote_addr = self.sturn_addr
        log.debug('First try: Find changed IP and external IP')
        first_try = await self._send_stun_request(remote_addr=remote_addr)
        log.debug('First try: %s', first_try)
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

        if first_try is None:
            raise Exception("Cannot receive UDP. All ports may be blocked.")
        elif first_try['remote_addr'][0] in local_ips:
            log.info("Not natted device.")
            return NAT_TYPE.NAT_NONE, first_try['remote_addr']

        data_request_changed = ''.join(
            [STUN_CODE.CAHNGE_REQUEST, '0004', '00000006'])

        log.debug('second_try: Try getting packet from another IP/port')
        second_try = await self._send_stun_request(remote_addr, data_request_changed)
        log.debug('second_try: %s', second_try)
        if second_try is not None:
            return [NAT_TYPE.NAT_FULL, first_try['remote_addr']]

        log.debug('third_try: Send packet to changed address')
        third_try = await self._send_stun_request(first_try['change_addr'])
        log.debug('third_try: %s', third_try)
        if third_try is False:
            raise Exception("Cannot determine NAT type")

        if third_try['remote_addr'][0] == first_try['remote_addr'][0] and third_try['remote_addr'][1] == first_try['remote_addr'][1]:
            log.info("Restricted type NAT")
            return NAT_TYPE.NAT_RESTRICTED, first_try['remote_addr']
        return NAT_TYPE.NAT_SYMETRIC, second_try['remote_addr']

    async def _keepalive(self):
        while True:
            await asyncio.sleep(30)
            await self._get_public_addr()

    async def load(self):
        loop = asyncio.get_event_loop()
        server = self.app.root['Device']['ManagementServer']['STUNServerAddress'](
        )
        port = self.app.root['Device']['ManagementServer']['STUNServerPort'](
        )
        sturn_addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_UDP)
        print(sturn_addr_info)
        self.sturn_addr = sturn_addr_info[0][4]

        self.transport, self.protocol = await loop.create_datagram_endpoint(lambda: StunClientProtocol(self), local_addr=('0.0.0.0', 10340), family=socket.AF_INET)
        log.info("Start STUN discovery at: %s:%d", server, port)

        nat_type, public_address = await self._get_public_addr()
        self.app.root['Device']['ManagementServer']['NATDetected'](
            nat_type != NAT_TYPE.NAT_NONE)
        self.app.root['Device']['ManagementServer']['UDPConnectionRequestAddress'](
            public_address[0] + ":" + str(public_address[1]))

        print(nat_type)

        self.keepalive = asyncio.create_task(self._keepalive())

    async def unload(self):
        if self.keepalive != None:
            self.keepalive.cancel()
            await self.keepalive
