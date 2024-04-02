import asyncio
import logging
import binascii
import struct
import random
import socket
import hashlib
import hmac
import typing
import enum
from CwmpClient.app import App

log = logging.getLogger()


class STUN_MSG_TYPE(enum.Enum):
    REQ_BIND = b'\x00\x01'
    REQ_ALLOCATE = b'\x00\x03'


class STUN_RES_TYPE(enum.Enum):
    RES_ALLOCATE_ERROR = b'\x01\x13'
    RES_ALLOCATE_SUCESS = b'\x01\x03'


class STUN_MSG_ATTR(enum.Enum):
    ATTR_MAPPED_ADDR = b'\x00\01'
    ATTR_SOURCE_ADDR = b'\x00\x04'
    ATTR_CHANGE_ADDR = b'\x00\x05'
    ATTR_USERNAME = b'\x00\x06'
    ATTR_MSG_INTEGRITY = b'\x00\x08'
    ATTR_ERROR_CODE = b'\x00\x09'
    ATTR_CHANNEL_NUMBER = b'\x00\x0C'
    ATTR_LIFETIME = b'\x00\x0D'
    ATTR_XOR_PEER_ADDR = b'\x00\x12'
    ATTR_DATA = b'\x00\x13'
    ATTR_REALM = b'\x00\x14'
    ATTR_NONCE = b'\x00\x15'
    ATTR_XOR_RELAYED_ADDR = b'\x00\x16'
    ATTR_REQ_FAMILY = b'\x00\x17'
    ATTR_EVEN_PORT = b'\x00\x18'
    ATTR_REQ_TRANSPORT = b'\x00\x19'
    ATTR_DONT_FRAGMENT = b'\x00\x1A'
    ATTR_XOR_MAPPED_ADDR = b'\x00\x20'
    ATTR_RESERVATION_TOKEN = b'\x00\x22'

    ATTR_SOFTWARE = b'\x80\x22'


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


class StunResponse:
    def __init__(self, transid) -> None:
        self.transid = transid
        self.attr: typing.Dict[STUN_MSG_ATTR, any] = dict()

    def set(self, attr: STUN_MSG_ATTR, value: bytes):
        self.attr[attr] = value

    def getXorAddress(self, attr: STUN_MSG_ATTR):
        data = self.attr[attr]
        family, = struct.unpack_from('c', data, 1)
        port, = struct.unpack_from('>h', data ^ self.transid[0:2], 2)
        ip = data[4:8] ^ self.transid[0:4]

        log.debug('Family: %d, X-Port: %d, X-Addr: %s', family,
                  port, ip.hex())

    @staticmethod
    def frombytes(data) -> 'StunResponse':
        if data[4:8] != b'\x21\x12\xa4\x42':
            raise Exception('Bad magic cookie %s', data[4:8].hex())

        transid = data[8:20]
        is_error = False
        log.debug('Get transId %s', transid.hex())
        if data[0:2] == STUN_RES_TYPE.RES_ALLOCATE_ERROR.value:
            res = StunAllocationError(transid)
            is_error = True
        elif data[0:2] == STUN_RES_TYPE.RES_ALLOCATE_SUCESS.value:
            res = StunResponse(transid)
        else:
            raise NotImplementedError(
                'Response type %s not implemanted', data[0:2].hex())

        msg_len, = struct.unpack_from('>h', data, 2)
        print(msg_len)
        pos_reader = 20
        while pos_reader < msg_len:
            attr_len, = struct.unpack_from('>h', data, pos_reader+2)
            try:
                attr = STUN_MSG_ATTR(data[pos_reader:pos_reader+2])
                log.debug('Attr %s (len %d) = %s', attr, attr_len,
                          data[pos_reader+4:pos_reader+4+attr_len])
                res.set(attr, data[pos_reader+4:pos_reader+4+attr_len])
            except ValueError:
                log.warn('Unknow attribute %s',
                         data[pos_reader:pos_reader+2].hex())
            pos_reader += 4 + attr_len + (attr_len % 4)

        if is_error:
            raise res
        return res


class StunAllocationError(StunResponse, Exception):
    pass


class StunMessage:
    MAGIC_COOKIE = b'\x21\x12\xa4\x42'

    def __init__(self, type: STUN_MSG_TYPE, clientHandler: 'STUN_client' = None) -> None:
        self.type = type
        self.tranid = random.randbytes(12)
        self.attrs: typing.Dict[STUN_MSG_ATTR, bytes] = dict()
        self.client = clientHandler

    def copy(self) -> 'StunMessage':
        newobj = StunMessage(self.type, self.client)
        newobj.attrs = self.attrs.copy()
        return newobj

    def set(self, attr: STUN_MSG_ATTR, *value: any):
        if attr == STUN_MSG_ATTR.ATTR_DONT_FRAGMENT:
            if len(value) != 0:
                raise Exception('Bad number of arguments')
            self.attrs[attr] = b''
        elif attr == STUN_MSG_ATTR.ATTR_REQ_TRANSPORT:
            if len(value) != 1:
                raise Exception('Bad number of arguments')
            self.attrs[attr] = struct.pack('b', value[0]) + b'\x00\x00\x00'
        elif attr == STUN_MSG_ATTR.ATTR_MSG_INTEGRITY:
            if len(value) == 0:
                self.attrs[attr] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif attr == STUN_MSG_ATTR.ATTR_USERNAME:
            if len(value) == 0:
                raise Exception('Bad number of arguments')
            self.attrs[attr] = str.encode(value[0])
        else:
            if len(value) != 1:
                raise Exception('Bad number of arguments')
            self.attrs[attr] = value[0]

    def data(self) -> bytes:
        data = bytearray(b''.join([self.type.value, b'\x00\x00',
                         self.MAGIC_COOKIE, self.tranid]))
        msg_len = 0

        for attr_type, attr_content in self.attrs.items():
            log.debug('Pack %s = %s', attr_type, attr_content)
            data.extend(attr_type.value)
            data.extend(struct.pack('>h', len(attr_content)))
            data.extend(attr_content)
            trailling = len(attr_content) % 4
            if trailling != 0:
                for _ in range(4 - trailling):
                    data.extend(b'\x00')

            if attr_type == STUN_MSG_ATTR.ATTR_MSG_INTEGRITY:
                struct.pack_into('>h', data, 2, len(data) - 20)
                key = b''.join([str.encode(self.client.user), b':',
                                self.attrs[STUN_MSG_ATTR.ATTR_REALM], b':', str.encode(self.client.password)])
                md5_key = hashlib.md5(key)
                integrity = hmac.HMAC(
                    md5_key.digest(), data[0:-24], hashlib.sha1)
                data[len(data) - 20:] = integrity.digest()

            log.debug('Attr Type: %s, %d, %s', attr_type.value.hex(), len(
                attr_content), attr_content.hex())
            msg_len += len(attr_content) + 4

        struct.pack_into('>h', data, 2, len(data) - 20)

        log.debug('Len: %s, Dat: %s', msg_len,
                  struct.pack('>h', msg_len).hex())

        return data

    def __repr__(self) -> str:
        return ''.join(['StunMessage[', self.data().hex(), ']'])

    async def sendto(self, stunClient: 'STUN_client' = None, addr=None) -> StunResponse:
        if stunClient is None:
            if self.client is None:
                raise AssertionError("Client not defined")
            stunClient = self.client
        stunClient.results[self.tranid] = asyncio.get_event_loop(
        ).create_future()

        try:
            log.debug('Try send to : %s',
                      addr if addr is not None else stunClient.sturn_addr)
            for _ in range(5):
                stunClient.transport.sendto(
                    self.data(), addr if addr is not None else stunClient.sturn_addr)
                await asyncio.wait([stunClient.results[self.tranid]], timeout=1)
                if stunClient.results[self.tranid].done():
                    return stunClient.results[self.tranid].result()

            raise ConnectionRefusedError()
        except StunAllocationError as err:
            if err.attr[STUN_MSG_ATTR.ATTR_ERROR_CODE][2:4] == b'\x04\x01' and STUN_MSG_ATTR.ATTR_MSG_INTEGRITY not in self.attrs:
                log.debug('Authentication needed')
                auth_msg = self.copy()
                auth_msg.set(STUN_MSG_ATTR.ATTR_USERNAME, stunClient.user)
                auth_msg.set(STUN_MSG_ATTR.ATTR_REALM,
                             err.attr[STUN_MSG_ATTR.ATTR_REALM])
                auth_msg.set(STUN_MSG_ATTR.ATTR_NONCE,
                             err.attr[STUN_MSG_ATTR.ATTR_NONCE])
                auth_msg.set(STUN_MSG_ATTR.ATTR_MSG_INTEGRITY)
                return await auth_msg.sendto(stunClient, addr)

            else:
                log.error('Unknown error code: %s',
                          err.attr[STUN_MSG_ATTR.ATTR_ERROR_CODE][2:4].hex())
                raise err
        finally:
            del stunClient.results[self.tranid]


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

        try:
            res = StunResponse.frombytes(data)
            self.client.results[res.transid].set_result(res)
        except StunAllocationError as err:
            self.client.results[err.transid].set_exception(err)
        return

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
        self.results: typing.Dict[bytes, StunResponse] = dict()
        self.user: str = None
        self.password: str = None

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
        allocation = StunMessage(STUN_MSG_TYPE.REQ_ALLOCATE, self)
        allocation.set(STUN_MSG_ATTR.ATTR_REQ_TRANSPORT,
                       socket.IPPROTO_UDP)
        allocation.set(STUN_MSG_ATTR.ATTR_LIFETIME, b'\x00\x00\x03\x09')
        allocation.set(STUN_MSG_ATTR.ATTR_EVEN_PORT, b'\x80')
        allocation.set(STUN_MSG_ATTR.ATTR_REQ_FAMILY, b'\x01\x00\x00\x00')
        allocation.set(STUN_MSG_ATTR.ATTR_DONT_FRAGMENT)
        print(allocation)
        return await allocation.sendto(self)

    async def load(self):
        loop = asyncio.get_event_loop()
        server = self.app.root['Device']['ManagementServer']['STUNServerAddress'](
        )
        port = self.app.root['Device']['ManagementServer']['STUNServerPort'](
        )
        self.user = self.app.root['Device']['ManagementServer']['STUNUsername'](
        )
        self.password = self.app.root['Device']['ManagementServer']['STUNPassword'](
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
        mapped = await self._start_turn()
        log.info('Public IP: %s, Relai IP: %s', mapped.getXorAddress(
            STUN_MSG_ATTR.ATTR_XOR_MAPPED_ADDR), mapped.getXorAddress(STUN_MSG_ATTR.ATTR_XOR_RELAYED_ADDR))
        self.keepalive = asyncio.create_task(self._keepalive())
        await asyncio.sleep(100)

    async def unload(self):
        if self.keepalive != None:
            self.keepalive.cancel()
            await self.keepalive
