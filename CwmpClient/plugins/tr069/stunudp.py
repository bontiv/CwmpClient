from CwmpClient.nodes import ConfigFileParameter
import asyncio
import logging
import binascii
import struct
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


class STUN_CODE:
    # Request type send to STUN

    REQ_CHANGE = b'\x00\x03'
    REQ_BIND = b'\x00\x01'
    REQ_REFRESH = b'\x00\x04'
    REQ_SEND = b'\x00\x06'
    REQ_DATA = b'\x00\x07'
    REQ_CREATE_PERMISSION = b'\x00\x08'
    REQ_CHANNEL_BIND = b'\x00\x09'

    # Response from STUN
    RES_BIND = b'\x01\x01'
    RES_FORBIDDEN = 403
    RES_ALLOCATION_MISMATCH = 437
    RES_WRONG_CREDENTIALS = 441
    RES_UNSUPPORTED_PROTOCOL = 442
    RES_ALLOCATION_QUOTA_REACHED = 486
    RES_INSUFISANT_APACITY = 508

    # Message attributes
    ATTR_MAPPED_ADDR = b'\x00\01'
    ATTR_SOURCE_ADDR = b'\x00\x04'
    ATTR_CHANGE_ADDR = b'\x00\x05'
    ATTR_CHANNEL_NUMBER = b'\x00\x0C'
    ATTR_LIFETIME = b'\x00\x0C'
    ATTR_XOR_PEER_ADDR = b'\x00\x12'
    ATTR_DATA = b'\x00\x13'
    ATTR_XOR_RELAYED_ADDR = b'\x00\x16'
    ATTR_EVEN_PORT = b'\x00\x18'
    ATTR_REQ_TRANSPORT = b'\x00\x19'
    ATTR_DONT_FRAGMENT = b'\x00\x1A'
    ATTR_RESERVATION_TOKEN = b'\x00\x22'


class StunMessage:
    MAGIC_COOKIE = b'\x21\x12\xa4\x42'

    class MSG_TYPE(enum.Enum):
        REQ_BIND = b'\x00\x01'
        REQ_ALLOCATE = b'\x00\x03'

    class MSG_ATTR(enum.Enum):
        ATTR_MAPPED_ADDR = b'\x00\01'
        ATTR_SOURCE_ADDR = b'\x00\x04'
        ATTR_CHANGE_ADDR = b'\x00\x05'
        ATTR_CHANNEL_NUMBER = b'\x00\x0C'
        ATTR_LIFETIME = b'\x00\x0C'
        ATTR_XOR_PEER_ADDR = b'\x00\x12'
        ATTR_DATA = b'\x00\x13'
        ATTR_XOR_RELAYED_ADDR = b'\x00\x16'
        ATTR_EVEN_PORT = b'\x00\x18'
        ATTR_REQ_TRANSPORT = b'\x00\x19'
        ATTR_DONT_FRAGMENT = b'\x00\x1A'
        ATTR_RESERVATION_TOKEN = b'\x00\x22'

    def __init__(self, type: MSG_TYPE) -> None:
        self.type = type
        self.tranid = random.randbytes(24)
        self.attrs: typing.Dict[self.MSG_ATTR, bytes] = dict()

    def set(self, attr: MSG_ATTR, *value: any):
        if attr == self.MSG_ATTR.ATTR_DONT_FRAGMENT:
            if len(value) != 0:
                raise Exception('Bad number of arguments')
            self.attrs[attr] = b''

    def data(self) -> bytes:
        data = bytearray()
        data.extend(b'\x00\x00')
        data.extend(self.MAGIC_COOKIE)
        data.extend(self.tranid)
        msg_len = 0
        for attr_type, attr_content in self.attrs.items():
            data.extend(attr_type.value)
            data.extend(struct.pack('h', len(attr_content)))
            data.extend(attr_content)
            msg_len += len(attr_content)

        return b''.join([self.type.value, struct.pack('h', msg_len), self.MAGIC_COOKIE, self.tranid, data])

    def __repr__(self) -> str:
        return ''.join(['StunMessage[', self.data().hex(), ']'])

    async def sendto(self, transport: asyncio.DatagramTransport, addr=None):
        transport.sendto(self.data(), addr)


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
        msgtype = data[0:2]
        if msgtype == STUN_CODE.RES_BIND:  # Response type
            log.debug('Get STUN packet')
            if self.client.tranid.upper() != b2a_hexstr(data[4:20]).upper():
                log.error('Cookie not valid. This packet cannot be executed')
                return

            len_message = int(b2a_hexstr(data[2:4]), 16)
            len_remain = len_message
            ptr = 20
            while len_remain:
                attr_type = data[ptr:(ptr + 2)]
                attr_len = int(b2a_hexstr(data[(ptr + 2):(ptr + 4)]), 16)
                if attr_type == STUN_CODE.ATTR_MAPPED_ADDR:
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

                elif attr_type == STUN_CODE.ATTR_SOURCE_ADDR:
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

                elif attr_type == STUN_CODE.ATTR_CHANGE_ADDR:
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

    async def _send_stun_request(self, remote_addr: typing.Tuple[str, int] = None, send_data=b'', req_type=STUN_CODE.REQ_BIND):
        if remote_addr is None:
            remote_addr = self.sturn_addr
        self.tranid = '2112a442' + ''.join(random.choice('0123456789ABCDEF')
                                           for i in range(24))
        str_len = "%#04d" % len(send_data)
        str_data = ''.join(
            [str_len, self.tranid])
        data = req_type + binascii.a2b_hex(str_data) + send_data
        self._last_response: asyncio.Future[StunResponse] = asyncio.Future()
        log.debug('Send to: %s, Data: %s', remote_addr, data)

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

        data_request_changed = STUN_CODE.REQ_CHANGE + b'\x00\x04' + b'\x00\x00\x00\x06'

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
            await asyncio.sleep(600)  # Default timeout 10 mins for Keepalive
            await self._get_public_addr()

    async def _start_turn(self):
        allocation = StunMessage(StunMessage.MSG_TYPE.REQ_ALLOCATE)
        allocation.set(StunMessage.MSG_ATTR.ATTR_DONT_FRAGMENT)
        allocation.set(StunMessage.MSG_ATTR.ATTR_REQ_TRANSPORT,
                       socket.IPPROTO_UDP)
        print(allocation)
        await allocation.sendto(self.transport, self.sturn_addr)

    async def load(self):
        loop = asyncio.get_event_loop()
        server = self.app.root['Device']['ManagementServer']['STUNServerAddress'](
        )
        port = self.app.root['Device']['ManagementServer']['STUNServerPort'](
        )
        sturn_addr_info = await loop.getaddrinfo(server, port, proto=socket.IPPROTO_UDP, family=socket.AF_INET)
        print(sturn_addr_info)
        self.sturn_addr = sturn_addr_info[0][4]

        self.transport, self.protocol = await loop.create_datagram_endpoint(lambda: StunClientProtocol(self), local_addr=('0.0.0.0', 10340), family=socket.AF_INET)
        log.info("Start STUN discovery at: %s:%d", server, port)

        # nat_type, public_address = await self._get_public_addr()
        # self.app.root['Device']['ManagementServer']['NATDetected'](
        #     nat_type != NAT_TYPE.NAT_NONE)
        # self.app.root['Device']['ManagementServer']['UDPConnectionRequestAddress'](
        #     public_address[0] + ":" + str(public_address[1]))

        # print(nat_type)

        # Require TURN protocol
        await self._start_turn()
        self.keepalive = asyncio.create_task(self._keepalive())
        await self.keepalive

    async def unload(self):
        if self.keepalive != None:
            self.keepalive.cancel()
            await self.keepalive
