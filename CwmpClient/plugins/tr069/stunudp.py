import asyncio
import logging
import struct
import random
import socket
import hashlib
import hmac
import typing
import enum
from CwmpClient.app import App
from CwmpClient.plugins.tr069.session import Tr69Inform

log = logging.getLogger()

""" Magic cookie """
MAGIC_COOKIE = b'\x21\x12\xa4\x42'


def xor_encrypt(var, key):
    """ XOR encrypt/decrypt

    Arguments:
        var [bytes] -- Data to process
        key [bytes] -- The key

    Returns:
        [bytes] The encrypted / descrypted data
    """
    return bytes(a ^ b for a, b in zip(var, key))


class STUN_MSG_TYPE(enum.Enum):
    """
    Stun message type (client to server)
    """
    REQ_BIND = b'\x00\x01'
    REQ_ALLOCATE = b'\x00\x03'
    REQ_SEND = b'\x00\x07'
    REQ_DATA = b'\x00\x07'
    REQ_CREATE_PERMISSION = b'\x00\x08'
    REQ_CHANNEL_BIND = b'\x00\x09'


class STUN_RES_TYPE(enum.Enum):
    """
    Stun response type (server to client)
    """
    RES_BIND = b'\x01\x01'
    RES_ALLOCATE_SUCESS = b'\x01\x03'
    RES_CREATE_PERMISSION = b'\x01\x08'
    RES_ALLOCATE_ERROR = b'\x01\x13'
    RES_SEND_INDICATION = b'\x00\x17'  # For reading incomming packet


class STUN_MSG_ATTR(enum.Enum):
    """
    Stun and turn attributes
    """
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


class StunResponse:
    """Represent a message from STUN server
    """

    def __init__(self, transid) -> None:
        """Create a stun response

        Arguments:
            transid [bytes] -- Transaction ID of origin message
        """
        self.transid = transid
        self.attrs: typing.Dict[STUN_MSG_ATTR, typing.Any] = dict()
        self.type: STUN_RES_TYPE | None = None

    def set(self, attr: STUN_MSG_ATTR, value: bytes):
        """Set an attribute in response

        Arguments:
            attr -- STUN attribute
            value -- Value
        """
        self.attrs[attr] = value

    def getXorAddress(self, attr: STUN_MSG_ATTR):
        """Decode an attribute as IP and port tuple

        Arguments:
            attr -- Attribute to decode

        Returns:
            [tuple[str,int]] Tuple of IP (str) and port (int)
        """
        data = self.attrs[attr]
        family, = struct.unpack_from('c', data, 1)
        port, = struct.unpack('>H', xor_encrypt(data[2:4], MAGIC_COOKIE))
        ip = xor_encrypt(data[4:8], MAGIC_COOKIE)
        ip = '.'.join([str(int(c)) for c in ip])

        log.debug('Family: %s, X-Port: %s, X-Addr: %s', family,
                  port, ip)
        return ip, port

    def __repr__(self) -> str:
        repr = "StunResponse<{}>[TransId:{},{}]".format(
            self.type, self.transid, ','.join([key.name + '=' + item.hex() for key, item in self.attrs.items()]))
        return repr

    @staticmethod
    def frombytes(data) -> 'StunResponse':
        """Factory create StunResponse from received bytes

        Arguments:
            data -- Bytes to unserialize as StunResponse

        Raises:
            NotImplementedError: The response type is unknown (no implementation)
            StunAllocationError: The decoded message is an error

        Returns:
            The StunResponse
        """
        if data[4:8] != MAGIC_COOKIE:
            raise Exception('Bad magic cookie %s', data[4:8].hex())

        transid = data[8:20]
        is_error = False
        log.debug('Get transId %s', transid.hex())
        if data[0:2] == STUN_RES_TYPE.RES_ALLOCATE_ERROR.value:
            res = StunAllocationError(transid)
            is_error = True
        else:
            try:
                res = StunResponse(transid)
                res.type = STUN_RES_TYPE(data[0:2])
            except ValueError:
                raise NotImplementedError(
                    'Response type %s not implemanted', data[0:2].hex())

        msg_len, = struct.unpack_from('>h', data, 2)

        pos_reader = 20
        while pos_reader < msg_len:
            attr_len, = struct.unpack_from('>H', data, pos_reader+2)
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
    def __init__(self, type: STUN_MSG_TYPE, clientHandler: 'STUN_client|None' = None) -> None:
        """Create a new STUN Request

        Arguments:
            type -- Type of request

        Keyword Arguments:
            clientHandler -- STUN_Client (default: {None})
        """
        self.type = type
        self.tranid = random.randbytes(12)
        self.attrs: typing.Dict[STUN_MSG_ATTR, bytes] = dict()
        self.client = clientHandler

    def copy(self) -> 'StunMessage':
        """Create a new StunMEssage derived from this StunMessage.
        The new message will have another transaction ID and all same attributes.

        Returns:
            New StunMessage
        """
        newobj = StunMessage(self.type, self.client)
        newobj.attrs = self.attrs.copy()
        return newobj

    def setXorAddress(self, attr: STUN_MSG_ATTR, addr):
        """Set attribute with IP/Port value
        IP and port will be XOR encoded.

        Arguments:
            attr -- Attribute to set
            addr -- Tuple of IP[str] and port[int]
        """
        data = bytearray(b'\x00\x01')
        data.extend(xor_encrypt(struct.pack('>H', addr[1]), MAGIC_COOKIE))
        data.extend(xor_encrypt(b''.join([struct.pack('B', int(x))
                    for x in addr[0].split('.')]), MAGIC_COOKIE))

        self.attrs[attr] = bytes(data)

    def auth(self, client: 'STUN_client|None' = None) -> None:
        """Add authentication on this message
        Authentication is based from STUN_Client attributes.

        Keyword Arguments:
            client -- Client to use to get credentials. Use client from __init__ if not set. (default: {None})

        Raises:
            ValueError: No 
        """
        if client is None:
            client = self.client
            if client is None:
                raise ValueError('STUN client must be defined')

        self.set(STUN_MSG_ATTR.ATTR_USERNAME,
                 client.user)
        self.set(STUN_MSG_ATTR.ATTR_NONCE, client.nonce)
        self.set(STUN_MSG_ATTR.ATTR_REALM, client.realm)
        self.set(STUN_MSG_ATTR.ATTR_MSG_INTEGRITY)

    def set(self, attr: STUN_MSG_ATTR, *value: typing.Any):
        """Set Attribute in Message

        Arguments:
            attr -- Attribute to set
            *value -- Value to set

        Raises:
            ValueError: Incorrect value type or number
        """
        if attr == STUN_MSG_ATTR.ATTR_DONT_FRAGMENT:
            if len(value) != 0:
                raise ValueError('Bad number of arguments')
            self.attrs[attr] = b''
        elif attr == STUN_MSG_ATTR.ATTR_REQ_TRANSPORT:
            if len(value) != 1:
                raise ValueError('Bad number of arguments')
            self.attrs[attr] = struct.pack('b', value[0]) + b'\x00\x00\x00'
        elif attr == STUN_MSG_ATTR.ATTR_MSG_INTEGRITY:
            if len(value) == 0:
                self.attrs[attr] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif attr == STUN_MSG_ATTR.ATTR_USERNAME:
            if len(value) == 0:
                raise ValueError('Bad number of arguments')
            self.attrs[attr] = str.encode(value[0])
        else:
            if len(value) != 1:
                raise ValueError('Bad number of arguments')
            self.attrs[attr] = value[0]

    def data(self) -> bytes:
        """Get message in bytes

        Raises:
            ValueError: User and password not defined

        Returns:
            [bytes] UDP packet in bytes format
        """
        data = bytearray(b''.join([self.type.value, b'\x00\x00',
                         MAGIC_COOKIE, self.tranid]))
        msg_len = 0

        for attr_type, attr_content in self.attrs.items():
            log.debug('Pack %s = %s', attr_type, attr_content)
            data.extend(attr_type.value)
            data.extend(struct.pack('>H', len(attr_content)))
            data.extend(attr_content)
            trailling = len(attr_content) % 4
            if trailling != 0:
                for _ in range(4 - trailling):
                    data.extend(b'\x00')

            if attr_type == STUN_MSG_ATTR.ATTR_MSG_INTEGRITY:
                struct.pack_into('>H', data, 2, len(data) - 20)
                if self.client is None or self.client.user is None or self.client.password is None:
                    raise ValueError('No user and password defined')
                key = b''.join([str.encode(self.client.user), b':',
                                self.attrs[STUN_MSG_ATTR.ATTR_REALM], b':', str.encode(self.client.password)])
                md5_key = hashlib.md5(key)
                integrity = hmac.HMAC(
                    md5_key.digest(), data[0:-24], hashlib.sha1)
                data[len(data) - 20:] = integrity.digest()

            log.debug('Attr Type: %s, %d, %s', attr_type.value.hex(), len(
                attr_content), attr_content.hex())
            msg_len += len(attr_content) + 4

        struct.pack_into('>H', data, 2, len(data) - 20)

        log.debug('Len: %s, Dat: %s', msg_len,
                  struct.pack('>H', msg_len).hex())

        return data

    def __repr__(self) -> str:
        return ''.join(['StunMessage[', self.data().hex(), ']'])

    async def sendto(self, stunClient: 'STUN_client|None' = None, addr=None) -> StunResponse:
        """Send this message

        Keyword Arguments:
            stunClient -- Client for transport and authentication. Use client from __init__ if not set (default: {None})
            addr -- Destination tuple (ip[str], port[int]) (default: {None})

        Raises:
            AssertionError: Client is not defined
            ConnectionRefusedError: Cannot send data (timeout)
            StunAllocationError: Receive error from server

        Returns:
            [StunResponse] Response decoded from server
        """
        if stunClient is None and self.client is not None:
            stunClient = self.client
        elif stunClient is None:
            raise AssertionError("Client not defined")

        if stunClient.transport is None:
            raise AssertionError('Try to send without transport')

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
            if err.attrs[STUN_MSG_ATTR.ATTR_ERROR_CODE][2:4] == b'\x04\x01' and STUN_MSG_ATTR.ATTR_MSG_INTEGRITY not in self.attrs:
                log.debug('Authentication needed')
                auth_msg = self.copy()
                stunClient.realm = err.attrs[STUN_MSG_ATTR.ATTR_REALM]
                stunClient.nonce = err.attrs[STUN_MSG_ATTR.ATTR_NONCE]
                auth_msg.auth(stunClient)
                return await auth_msg.sendto(stunClient, addr)

            else:
                log.error('Unknown error code: %s',
                          err.attrs[STUN_MSG_ATTR.ATTR_ERROR_CODE][2:4].hex())
                raise err
        finally:
            del stunClient.results[self.tranid]


class StunClientProtocol(asyncio.DatagramProtocol):
    """Protocol for STUN
    """

    def __init__(self, client: 'STUN_client') -> None:
        """Create a StunClientProtocol

        Arguments:
            client -- [STUN_Client] for communication
        """
        super().__init__()
        """Client for communciation
        """
        self.client = client
        """Last transactions for dedup
        """
        self.last_trans: typing.List[bytes] = []

    def datagram_received(self, data, addr):
        """Receive a UDP packet
        Process depends on if packet is STUN packet or other packet

        Arguments:
            data -- Packet Data
            addr -- Sender
        """
        log.info("Receiving UDP %s:%d = %s",
                 addr[0], addr[1], data.hex())
        try:
            res = StunResponse.frombytes(data)
            if res.type == STUN_RES_TYPE.RES_SEND_INDICATION:
                self.client.process(res.attrs[STUN_MSG_ATTR.ATTR_DATA])
            elif res.transid in self.client.results:
                self.client.results[res.transid].set_result(res)
        except StunAllocationError as err:
            if err.transid in self.client.results:
                self.client.results[err.transid].set_exception(err)


class STUN_client:
    """A Stun client for TR-069
    """

    def __init__(self, app: App):
        """Class represent STUN Client

        Arguments:
            app -- TR-069 global app
        """
        self.app = app
        self.protocol: StunClientProtocol | None = None
        self.transport: asyncio.DatagramTransport | None = None
        self.keepalive: asyncio.Task | None = None
        self._last_response: asyncio.Future | None = None
        self.sturn_addr: typing.Tuple[str, int] | None = None
        self.results: typing.Dict[bytes, asyncio.futures.Future] = dict()
        self.user: str | None = None
        self.password: str | None = None
        self.nonce: bytes | None = None
        self.realm: bytes | None = None
        self.tasks: typing.List[asyncio.Task] = []

    async def _keepalive(self):
        while True:
            await asyncio.sleep(600)  # Default timeout 10 mins for Keepalive

    def process(self, data: bytes) -> None:
        text = data.decode()
        print('Data received ! : ' + text)

        # On data received, launch session
        req = Tr69Inform(self.app, '6 CONNECTION REQUEST')
        self.tasks.append(asyncio.create_task(req.run()))
        for task in self.tasks:
            if task.done():
                self.tasks.remove(task)

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

    async def _detect_nat(self):
        bind_test = StunMessage(STUN_MSG_TYPE.REQ_BIND, self)
        result_bind = await bind_test.sendto()
        log.debug(result_bind.getXorAddress(
            STUN_MSG_ATTR.ATTR_XOR_MAPPED_ADDR))

        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]

        return result_bind.getXorAddress(
            STUN_MSG_ATTR.ATTR_XOR_MAPPED_ADDR) not in local_ips

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
        self.sturn_addr = (sturn_addr_info[0][4][0], sturn_addr_info[0][4][1])

        self.transport, self.protocol = await loop.create_datagram_endpoint(lambda: StunClientProtocol(self), local_addr=('0.0.0.0', random.randint(49152, 65535)), family=socket.AF_INET)
        log.info("Start STUN discovery at: %s:%d", server, port)

        is_nated = await self._detect_nat()
        self.app.root['Device']['ManagementServer']['NATDetected'](is_nated)

        if is_nated:
            public_nat = await self._start_turn()
            public_address = public_nat.getXorAddress(
                STUN_MSG_ATTR.ATTR_XOR_RELAYED_ADDR)

            log.info('Use public interface %s:%d',
                     public_address[0], public_address[1])

            self.app.root['Device']['ManagementServer']['UDPConnectionRequestAddress'](
                public_address[0] + ":" + str(public_address[1]))

            # Create permission
            perms = StunMessage(STUN_MSG_TYPE.REQ_CREATE_PERMISSION, self)
            perms.setXorAddress(
                STUN_MSG_ATTR.ATTR_XOR_PEER_ADDR, self.sturn_addr)
            perms.set(STUN_MSG_ATTR.ATTR_USERNAME, self.user)
            perms.auth(self)
            perms_resp = await perms.sendto()
            log.debug(perms_resp)

    async def unload(self):
        if self.keepalive != None:
            self.keepalive.cancel()
            await self.keepalive

        await asyncio.wait(self.tasks, timeout=5)
