import asyncio
import base64
import json
import pyarchy
import socket
import struct

from concurrent.futures import TimeoutError

from . import constants, security


class Datagram(object):

    @classmethod
    def from_string(cls, str_: str):
        return cls(**json.loads(str_))

    def __init__(self,
                 command: int = None,
                 sender: str = None, recipient: str = None,
                 data: str = None, hmac: str = None):
        object.__init__(self)

        self.__command = command
        self.__sender = sender
        self.__recipient = recipient
        self.__data = data
        self.__hmac = hmac

    def __str__(self):
        return json.dumps({
            'command': self.command,
            'sender': self.sender,
            'recipient': self.recipient,
            'data': self.data,
            'hmac': self.hmac,
        })

    @property
    def command(self):
        return self.__command

    @command.setter
    def command(self, command):
        self.__command = command

    @property
    def sender(self) -> str:
        return self.__sender

    @property
    def recipient(self) -> str:
        return self.__recipient

    @recipient.setter
    def recipient(self, recipient: str):
        self.__recipient = str(recipient)

    @property
    def route(self):
        return (self.sender, self.recipient)

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, data):
        if isinstance(data, bytes):
            self.__data = data.decode()
        else:
            self.__data = data

    @property
    def hmac(self):
        return self.__hmac


class Node(security.KeyHandler, pyarchy.common.ClassicObject):

    def __init__(self, stream_reader, stream_writer):
        security.KeyHandler.__init__(self)
        pyarchy.common.ClassicObject.__init__(self, '', False)

        self._stream_reader = stream_reader
        self._stream_writer = stream_writer

        self._commands = {
            constants.CMD_SHAKE: self.handle_handshake,
            constants.CMD_ERR: self.handle_error,
        }

    async def send(self, dg: Datagram):
        data = str(dg).encode()
        data = base64.b85encode(data)
        data = self.encrypt(data)

        n_bytes = len(data)
        pointer = struct.pack('I', socket.htonl(n_bytes))

        try:
            self._stream_writer.write(pointer + data)
            await self._stream_writer.drain()
        except ConnectionResetError:
            # Client crashed
            pass

    async def recv(self, n_bytes: int = None):
        try:
            if n_bytes is None:
                pointer = await self._stream_reader.readexactly(4)
                n_bytes = socket.ntohl(struct.unpack('I', pointer)[0])

            data = await self._stream_reader.read(n_bytes)
            data = self.decrypt(data)
            data = base64.b85decode(data).decode()
            return Datagram.from_string(data)
        except ConnectionResetError:
            # Client crashed
            pass
        except asyncio.streams.IncompleteReadError:
            # Failed to receive pointer
            pass
        except struct.error:
            # Received invalid pointer
            pass
        except json.decoder.JSONDecodeError:
            # Bad Datagram
            pass

        return None

    async def start(self):
        await self.send_handshake()

        # Maintain the connection
        while True:
            dg = await self.recv()
            if not dg:
                break

            if await self.handle_datagram(dg):
                break

    async def stop(self):
        self._stream_writer.close()

    async def handle_datagram(self, dg: Datagram):
        func = self._commands.get(dg.command)
        if func:
            await func(dg)
        else:
            await self.send_error(constants.ERR_DISCONNECT)

    async def send_handshake(self):
        await self.send(
            Datagram(
                command = constants.CMD_SHAKE,
                sender = self.id,
                recipient = self.id,
                data = self.key))

    async def handle_handshake(self, dg: Datagram):
        self.counter_key = int(dg.data)

    async def send_error(self, errno: int):
        await self.send(
            Datagram(
                command = constants.CMD_ERR,
                sender = self.id,
                recipient = self.id,
                data = errno))

    # Add functionality in subclass
    async def handle_error(self, dg: Datagram):
        return NotImplemented

    async def send_response(self, data):
        await self.send(
            Datagram(
                command = constants.CMD_RESP,
                sender = self.id,
                recipient = self.id,
                data = data))


class ClientBase(Node):

    def __init__(self,
                 stream_reader, stream_writer,
                 hmac_key, challenge_key):
        Node.__init__(self, stream_reader, stream_writer)

        self._hmac_key = hmac_key or b''
        self._challenge_key = challenge_key or b''

        self._name = None

    def __lt__(self, obj):
        if isinstance(obj, pyarchy.core.NamedObject):
            return self.name < obj.name
        else:
            return NotImplemented

    def __gt__(self):
        if isinstance(obj, pyarchy.core.NamedObject):
            return self.name > obj.name
        else:
            return NotImplemented

    @property
    def name(self) -> str:
        return str(self._name)

    @name.setter
    def name(self, name: str):
        if self._name is None:
            self._name = str(name)
        else:
            raise AttributeError('name can only be set once')


__all__ = [
    Datagram,
    Node,
    ClientBase,
]
